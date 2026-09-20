package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pascalgross/hostseal/internal/protocol"
)

// migrationFiles holds the schema, embedded so the binary is self-contained.
//
// A single binary plus PostgreSQL is the whole deployment. Shipping migrations as separate files an
// operator has to place correctly would reintroduce exactly the friction that decision avoided.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// jobChannel is the LISTEN/NOTIFY channel that wakes job long-polls.
//
// Its payload is the host id, so one listener connection can serve the whole fleet. That fan-out is not
// a nicety: a design that opened a PostgreSQL connection per waiting agent would need five hundred
// connections to hold five hundred long-polls, which is more than most instances allow in total.
const jobChannel = "hostseal_job"

// Postgres is the production Store.
type Postgres struct {
	// pool serves ordinary queries.
	pool *pgxpool.Pool

	// dsn is kept because the listener needs its own connection, outside the pool.
	//
	// A connection running LISTEN cannot be returned to a pool and reused for queries without losing
	// the subscription, so it is held separately for the process's lifetime.
	dsn string

	// mu guards waiters.
	mu sync.Mutex

	// waiters maps a host id to the channels waiting for work for it.
	waiters map[string][]chan struct{}

	// listenerOnce ensures the single listener goroutine is started at most once.
	listenerOnce sync.Once

	// closed is closed when the store shuts down, stopping the listener.
	closed chan struct{}

	// ready is closed once the listener has issued its first LISTEN.
	//
	// Nothing on the request path waits for it: a notification that arrives before the listener is
	// established is the same bounded gap as one that arrives while it is reconnecting, and blocking a
	// long-poll on a database connection that may never come back would turn a latency problem into an
	// availability one. It exists so that a test can wait for the listener instead of sleeping and
	// hoping, which is the difference between a test that fails when the code breaks and one that fails
	// on a slow machine.
	ready chan struct{}

	// readyOnce guards closing ready, which happens on every successful LISTEN and must happen once.
	readyOnce sync.Once
}

// OpenPostgres connects to PostgreSQL and returns a Store.
//
// It does not run migrations; the caller decides when, so that a replica rolling out during a deploy
// does not race another replica's migration.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parsing the database URL: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connecting: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: connecting: %w", err)
	}
	return &Postgres{
		pool:    pool,
		dsn:     dsn,
		waiters: map[string][]chan struct{}{},
		closed:  make(chan struct{}),
		ready:   make(chan struct{}),
	}, nil
}

// Ping reports whether the database is reachable, and reads nothing.
//
// pgx's own Ping rather than a hand-written `SELECT 1`, because it is the same round trip and it is
// the one the pool understands: it takes a connection from the pool and returns it, so what this
// answers is "a pooled connection can complete a statement", which is exactly the question the health
// endpoint is asking on behalf of whatever restarts this process.
//
// It sets no tenant, and it does not need to. Every statement that touches tenant data goes through
// In(tenant) and runs inside a transaction that has set one; this reaches no table at all.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: pinging the database: %w", err)
	}
	return nil
}

// Close releases the pool and stops the listener.
func (p *Postgres) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	p.pool.Close()
	return nil
}

// Migrate applies every embedded migration that has not run yet.
//
// A PostgreSQL advisory lock serialises this across replicas: several instances starting at once must
// not run the same migration concurrently, and an advisory lock costs nothing when there is no
// contention. The lock number is arbitrary but must never change, which is why it is a named constant
// rather than a literal at the call site.
func (p *Postgres) Migrate(ctx context.Context) error {
	const migrationLock = 8_412_679_001

	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquiring a connection to migrate: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("store: taking the migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLock); err != nil {
			slog.Error("could not release the migration lock", "error", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS hostseal_schema_version (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("store: creating the version table: %w", err)
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		var applied bool
		if err := conn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM hostseal_schema_version WHERE version = $1)", name,
		).Scan(&applied); err != nil {
			return fmt.Errorf("store: checking migration %s: %w", name, err)
		}
		if applied {
			continue
		}

		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: reading migration %s: %w", name, err)
		}
		if _, err := conn.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("store: applying migration %s: %w", name, err)
		}
		if _, err := conn.Exec(ctx,
			"INSERT INTO hostseal_schema_version (version) VALUES ($1)", name,
		); err != nil {
			return fmt.Errorf("store: recording migration %s: %w", name, err)
		}
		slog.Info("applied database migration", "migration", name)
	}
	return nil
}

// migrationNames lists the embedded migrations in lexical order.
//
// Lexical order is the apply order, which is why the files are numbered. Sorting explicitly rather than
// relying on the filesystem means the order is the same on every platform.
func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: reading embedded migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// In returns everything an operator or an agent can reach, scoped to one tenant.
//
// The handle is cheap on purpose — a pointer and a string, no connection — because it is made per
// request, from whichever tenant the request's certificate or credential resolved to.
func (p *Postgres) In(tenant TenantID) Scoped {
	return &scopedPostgres{p: p, tenant: tenant}
}

// scopedPostgres is Scoped for PostgreSQL: one tenant, and every statement inside a transaction that
// has said so.
//
// It is a type of its own rather than a tenant field on Postgres because a field would be shared by
// every request in flight, and because the split is what puts the two resolvers — the only operations
// that may legitimately run with no tenant at all — out of reach of the code that handles tenant data.
type scopedPostgres struct {
	// p is the store this handle borrows its pool and its error conventions from.
	p *Postgres

	// tenant is whose data this handle reaches. It is set on every transaction the handle opens.
	tenant TenantID
}

// Tenant reports whose data this handle reaches, for logs and for assertions.
func (s *scopedPostgres) Tenant() TenantID { return s.tenant }

// withTenant runs fn inside a transaction that has named this handle's tenant to PostgreSQL first.
//
// The third argument to set_config is what LOCAL means, and LOCAL is the load-bearing word: the
// setting is discarded when this transaction ends, so it cannot outlive the statements it was set for
// and be inherited by whichever request borrows the same pooled connection next. A session-level SET
// would leave one tenant's identity behind on a connection for the next caller to run their query
// under, which is this whole boundary failing in the quietest way available.
//
// It is set_config rather than SET LOCAL because SET takes no bind parameters. The only way to write
// it with SET is to build the statement by concatenation, and a tenant id is a value from outside —
// that is an injection site, in the one statement whose job is to say who is asking.
//
// Every scoped method goes through here, including the ones that are a single SELECT. A read needs the
// setting exactly as much as a write does: without it the policy matches nothing and the method
// returns an empty result rather than the row it was asked for. An exception "just for reads" is how a
// boundary like this acquires its first hole.
func (s *scopedPostgres) withTenant(ctx context.Context, what string, fn func(pgx.Tx) error) error {
	tx, err := s.p.pool.Begin(ctx)
	if err != nil {
		return wrap(err, what)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`SELECT set_config('hostseal.tenant', $1, true)`, string(s.tenant),
	); err != nil {
		return wrap(err, "setting the tenant while "+what)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return wrap(tx.Commit(ctx), what)
}

// withResolveKey runs fn inside a transaction that names one row's key, and no tenant at all.
//
// It is the narrow exception migration 0004 built into the policies on certificates and
// enrollment_tokens, and migration 0009 extended to operator_accounts and operator_sessions. Four
// lookups must happen before a tenant is known: an agent presents a certificate, a machine that is not
// yet a host presents an enrolment token, a sign-in form names an address, and a signed-in browser
// presents a session token. In each case finding the row is *how* the tenant is discovered. The policy
// admits exactly the one row whose key the caller has already named, so the exemption is a row wide
// instead of a table wide.
//
// Three of those four keys are a SHA-256 of something the caller holds, which is what makes naming one
// a poor way of finding another. The address is the exception and migration 0009 says so at the policy:
// what keeps a guessable key from being a disclosure there is the sign-in endpoint's uniform refusal,
// not this transaction.
//
// Nothing but those four resolvers may use it. A method that reached for this instead of withTenant
// would be asking the database for one row from any tenant at all, which is the thing hostseal.tenant
// exists to prevent.
func (p *Postgres) withResolveKey(ctx context.Context, what, key string, fn func(pgx.Tx) error) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return wrap(err, what)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`SELECT set_config('hostseal.resolve_key', $1, true)`, key,
	); err != nil {
		return wrap(err, "naming the row while "+what)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return wrap(tx.Commit(ctx), what)
}

// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
//
// This runs on every authenticated agent request, it is the revocation check, and it is where a
// request finds out which tenant it belongs to — so it names the row through hostseal.resolve_key
// rather than through a tenant it does not yet have. It is still a primary-key lookup; the transaction
// around it is what the policy costs, and it is worth it for the one query that decides whose data the
// rest of the request may touch.
func (p *Postgres) LookupCertificate(ctx context.Context, fingerprint string) (Certificate, error) {
	var c Certificate
	err := p.withResolveKey(ctx, "looking up a certificate", fingerprint, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT fingerprint, host_id, tenant_id, serial, issued_at, not_after, revoked,
			       COALESCE(revoked_at, 'epoch'::timestamptz),
			       COALESCE(superseded_at, 'epoch'::timestamptz)
			  FROM certificates
			 WHERE fingerprint = $1`, fingerprint,
		).Scan(&c.Fingerprint, &c.HostID, &c.TenantID, &c.Serial, &c.IssuedAt, &c.NotAfter,
			&c.Revoked, &c.RevokedAt, &c.SupersededAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return wrap(err, "looking up a certificate")
	})
	if err != nil {
		return Certificate{}, err
	}
	if c.RevokedAt.Unix() == 0 {
		c.RevokedAt = time.Time{}
	}
	if c.SupersededAt.Unix() == 0 {
		c.SupersededAt = time.Time{}
	}
	return c, nil
}

// TenantForEnrollmentToken returns the tenant a token belongs to, or ErrTokenUnusable.
//
// It reads and does not consume: the enrolment handler calls this first, to find out whose fleet the
// machine is joining, and a host retrying an enrolment it has already completed must not burn a second
// token in the course of being told no.
//
// Unknown, expired and already consumed all return the same error, exactly as ConsumeEnrollmentToken
// does. This is the earlier of the two answers an attacker can provoke, so it is the one that would
// leak the distinction if either did.
//
// The expiry is checked against the database's clock because the interface hands this one no other:
// a token within a clock skew of its deadline can therefore resolve here and then fail to consume,
// which is the same refusal by a different route and is not worth a second parameter.
func (p *Postgres) TenantForEnrollmentToken(ctx context.Context, hash string) (TenantID, error) {
	var tenant TenantID
	err := p.withResolveKey(ctx, "resolving an enrolment token", hash, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT tenant_id
			  FROM enrollment_tokens
			 WHERE hash = $1
			   AND consumed_at IS NULL
			   AND expires_at > now()`, hash,
		).Scan(&tenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenUnusable
		}
		return wrap(err, "resolving an enrolment token")
	})
	if err != nil {
		return "", err
	}
	return tenant, nil
}

// tenantColumns is the projection every tenant read shares.
//
// One list rather than three, so that a column added to the table cannot arrive on the tenant page and
// be missing from the tenant list, which reads as a bug in the interface rather than as the omission
// it is.
const tenantColumns = `id, slug, display_name, created_at, approval_mode, webhook_url, host_limit, suspended`

// scanTenant reads one tenant row, translating an absent one into ErrNotFound.
func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Slug, &t.DisplayName, &t.CreatedAt, &t.ApprovalMode, &t.WebhookURL,
		&t.HostLimit, &t.Suspended)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, wrap(err, "scanning a tenant")
}

// CreateTenant records a new tenant.
//
// It runs on the pool rather than through withTenant: `tenants` carries no policy, because a row in it
// is a tenant rather than something belonging to one, and reaching this method at all requires the
// platform credential.
//
// An empty id is refused here rather than left to the schema, which would accept it. Once any
// transaction on a connection has set hostseal.tenant and let it lapse, current_setting reports the
// empty string rather than NULL for the rest of that connection's life — so a tenant whose id was
// empty would be the one tenant a statement that named no tenant at all could still reach, which is
// the single row this boundary could not keep anybody out of.
func (p *Postgres) CreateTenant(ctx context.Context, t Tenant) error {
	if t.ID == "" {
		return errors.New("store: a tenant needs an id")
	}
	// A caller that did not set a creation time gets the database's clock, which is the same one the
	// column's own default would have used. Two replicas disagreeing by a second about when a tenant
	// was created is not worth a second source of truth.
	var createdAt *time.Time
	if !t.CreatedAt.IsZero() {
		createdAt = &t.CreatedAt
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, display_name, created_at, approval_mode, webhook_url,
		                     host_limit, suspended)
		VALUES ($1, $2, $3, COALESCE($4::timestamptz, now()), $5, $6, $7, $8)`,
		string(t.ID), t.Slug, t.DisplayName, createdAt, string(t.ApprovalMode), t.WebhookURL,
		t.HostLimit, t.Suspended)
	// wrap turns a unique violation into ErrConflict, which here is a slug somebody else already has —
	// or, for a caller that generates its own ids, an id that is already taken.
	return wrap(err, "creating a tenant")
}

// GetTenant returns one tenant, or ErrNotFound.
func (p *Postgres) GetTenant(ctx context.Context, id TenantID) (Tenant, error) {
	return scanTenant(p.pool.QueryRow(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, string(id)))
}

// ListTenants returns every tenant, oldest first.
//
// The id breaks ties, so that two tenants created in the same millisecond do not swap places between
// page loads for a reason nobody can see.
func (p *Postgres) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT `+tenantColumns+` FROM tenants ORDER BY created_at, id`)
	if err != nil {
		return nil, wrap(err, "listing tenants")
	}
	defer rows.Close()

	var out []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, wrap(rows.Err(), "listing tenants")
}

// UpdateTenant applies a tenant's display name, approval mode, webhook, host limit and suspension.
//
// The slug is deliberately not among the columns. It is what logs, support tickets and anything
// external refer to this tenant by, so a rename is refused by the API rather than half-applied here.
//
// A changed approval mode reaches jobs created afterwards and nothing already queued: each job records
// what it required when it was created, which is what stops relaxing this setting from releasing work
// that was queued under a stricter one.
func (p *Postgres) UpdateTenant(ctx context.Context, id TenantID, patch TenantPatch) (Tenant, error) {
	// COALESCE for the three fields where NULL cannot be the intended value, and an explicit flag for
	// host_limit, where it can: `COALESCE($6, host_limit)` would make "remove this fleet's limit"
	// indistinguishable from "leave it alone", which is the same conflation that made the provisioner
	// clear a limit on a misspelt argument.
	//
	// One statement, so there is no read-modify-write to lose a concurrent edit in, and RETURNING so
	// the caller renders the row that now exists rather than the one it assembled.
	var mode *string
	if patch.ApprovalMode != nil {
		s := string(*patch.ApprovalMode)
		mode = &s
	}

	row := p.pool.QueryRow(ctx, `
		UPDATE tenants
		   SET display_name  = COALESCE($2, display_name),
		       approval_mode = COALESCE($3, approval_mode),
		       webhook_url   = COALESCE($4, webhook_url),
		       host_limit    = CASE WHEN $5::boolean THEN $6::integer ELSE host_limit END,
		       suspended     = COALESCE($7, suspended)
		 WHERE id = $1
		 RETURNING `+tenantColumns,
		string(id), patch.DisplayName, mode, patch.WebhookURL,
		patch.SetHostLimit, patch.HostLimit, patch.Suspended)

	tenant, err := scanTenant(row)
	if errors.Is(err, ErrNotFound) {
		return Tenant{}, ErrNotFound
	}
	return tenant, wrap(err, "updating a tenant")
}

// DeleteTenant removes a tenant and everything belonging to it.
//
// The hosts, tokens, certificates, jobs and results go with it through the schema's ON DELETE CASCADE
// rather than through statements here, so a table added by a later migration cannot be forgotten by
// this function. That the cascade reaches rows this transaction has named no tenant for is not an
// oversight: PostgreSQL runs referential actions outside row-level security, deliberately, so that
// integrity cannot be defeated by a policy.
func (p *Postgres) DeleteTenant(ctx context.Context, id TenantID) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, string(id))
	if err != nil {
		return wrap(err, "deleting a tenant")
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateEnrollmentToken records a new token by its hash.
func (s *scopedPostgres) CreateEnrollmentToken(ctx context.Context, t EnrollmentToken) error {
	return s.withTenant(ctx, "creating an enrolment token", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO enrollment_tokens (hash, label, fleet_group, bootstrap, created_at, expires_at,
			                               tenant_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			t.Hash, t.Label, t.Group, t.Bootstrap, t.CreatedAt, t.ExpiresAt, string(s.tenant))
		return wrap(err, "creating an enrolment token")
	})
}

// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
//
// The conditions are in the UPDATE rather than in a preceding SELECT, so two agents presenting the
// same token in the same instant cannot both succeed. A check-then-update in the handler would let
// them, and the window is exactly as wide as the round trip between the two statements.
//
// The tenant is one of those conditions and not only the transaction's setting. A token belongs to the
// fleet it was issued for, and this is the statement that turns holding one into a host in that fleet.
func (s *scopedPostgres) ConsumeEnrollmentToken(ctx context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := s.withTenant(ctx, "consuming an enrolment token", func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE enrollment_tokens
			   SET consumed_at = $3, consumed_by_host = $2
			 WHERE hash = $1
			   AND tenant_id = $4
			   AND consumed_at IS NULL
			   AND expires_at > $3
			RETURNING hash, label, fleet_group, bootstrap, created_at, expires_at, consumed_at,
			          consumed_by_host`,
			hash, hostID, now, string(s.tenant),
		).Scan(&t.Hash, &t.Label, &t.Group, &t.Bootstrap, &t.CreatedAt, &t.ExpiresAt,
			&t.ConsumedAt, &t.ConsumedByHost)
		if errors.Is(err, pgx.ErrNoRows) {
			// Unknown, expired, already consumed and belonging to somebody else all arrive here and all
			// return the same error. Distinguishing them for the caller would mean distinguishing them
			// for whoever is guessing.
			return ErrTokenUnusable
		}
		return wrap(err, "consuming an enrolment token")
	})
	if err != nil {
		return EnrollmentToken{}, err
	}
	return t, nil
}

// ListEnrollmentTokens returns this tenant's tokens for the UI, newest first.
func (s *scopedPostgres) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	var out []EnrollmentToken
	err := s.withTenant(ctx, "listing enrolment tokens", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT hash, label, fleet_group, bootstrap, created_at, expires_at,
			       COALESCE(consumed_at, 'epoch'::timestamptz), COALESCE(consumed_by_host, '')
			  FROM enrollment_tokens
			 WHERE tenant_id = $1
			 ORDER BY created_at DESC`, string(s.tenant))
		if err != nil {
			return wrap(err, "listing enrolment tokens")
		}
		defer rows.Close()

		for rows.Next() {
			var t EnrollmentToken
			if err := rows.Scan(&t.Hash, &t.Label, &t.Group, &t.Bootstrap, &t.CreatedAt, &t.ExpiresAt,
				&t.ConsumedAt, &t.ConsumedByHost); err != nil {
				return wrap(err, "scanning an enrolment token")
			}
			if t.ConsumedAt.Unix() == 0 {
				t.ConsumedAt = time.Time{}
			}
			out = append(out, t)
		}
		return wrap(rows.Err(), "listing enrolment tokens")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateEnrolledHost records a newly enrolled host and its first certificate together.
//
// One transaction, because half an enrolment wedges the machine: the host row claims the machine-id
// hash, so a certificate that failed to record leaves a host that can neither authenticate nor enrol
// again. Rolling both back turns that into a retry the agent makes by itself. It is the same
// transaction that carries the tenant setting, which is why the two inserts and the isolation are one
// mechanism rather than two.
//
// The fleet's row is locked first and its host limit is checked inside that lock, which is the same
// shape as RenewCertificate's live-certificate cap and exists for the same reason: a limit checked in
// one statement and enforced in another is not a limit. Two machines with two valid tokens enrolling
// into a fleet with one slot left would otherwise both count three, both see room, and both write —
// and batch provisioning is exactly the situation that produces simultaneous enrolments. The lock is
// taken whether or not a limit is set, because enrolment happens once per machine in its lifetime and
// serialising it per fleet costs nothing worth a second code path.
//
// Locking the fleet before writing the host is also the only order used anywhere: nothing takes a host
// or certificate lock and then reaches for its tenant, so there is no cycle to deadlock on.
//
// Both rows are written with this handle's tenant rather than with whatever the Certificate carries.
// The handle is the authority on whose fleet is being joined; a certificate is a value the caller
// assembled, and the composite foreign key would refuse it anyway if the two disagreed.
func (s *scopedPostgres) CreateEnrolledHost(ctx context.Context, h Host, c Certificate) error {
	return s.withTenant(ctx, "recording an enrolment", func(tx pgx.Tx) error {
		var limit *int
		if err := tx.QueryRow(ctx,
			`SELECT host_limit FROM tenants WHERE id = $1 FOR UPDATE`,
			string(s.tenant)).Scan(&limit); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return wrap(err, "locking the fleet to enrol into it")
		}
		if limit != nil {
			// Active, not total: revoking a host is how an operator makes room for another, and a
			// limit measured against rows kept for the audit trail would make that impossible for a
			// reason nobody could see.
			var active int
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM hosts WHERE tenant_id = $1 AND NOT revoked`,
				string(s.tenant)).Scan(&active); err != nil {
				return wrap(err, "counting a fleet before enrolling into it")
			}
			if active >= *limit {
				return ErrHostLimitReached
			}
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO hosts (id, tenant_id, hostname, machine_id_hash, fleet_group, agent_version,
			                   enrolled_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7)`,
			h.ID, string(s.tenant), h.Hostname, h.MachineIDHash, h.Group, h.AgentVersion, h.EnrolledAt,
		); err != nil {
			return wrap(err, "creating a host")
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO certificates (fingerprint, host_id, tenant_id, serial, issued_at, not_after)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			c.Fingerprint, c.HostID, string(s.tenant), c.Serial, c.IssuedAt, c.NotAfter,
		); err != nil {
			return wrap(err, "recording a certificate")
		}
		return nil
	})
}

// hostColumns is the column list every host query selects, in the order scanHost expects.
//
// It is a constant shared by the three queries that return a host so that adding a column is one edit
// rather than three, and so that the three cannot drift into returning different shapes.
const hostColumns = `
	id, hostname, COALESCE(machine_id_hash, ''), fleet_group, agent_version, enrolled_at,
	COALESCE(last_seen, 'epoch'::timestamptz), boot_id, uptime_seconds, clock_offset_seconds, paused,
	facts_digest, policy_digest, signers_digest,
	COALESCE(facts, 'null'::jsonb), COALESCE(policy, 'null'::jsonb), COALESCE(signers, 'null'::jsonb),
	revoked`

// scanHost reads one host row.
func scanHost(row pgx.Row) (Host, error) {
	var h Host
	err := row.Scan(&h.ID, &h.Hostname, &h.MachineIDHash, &h.Group, &h.AgentVersion, &h.EnrolledAt,
		&h.LastSeen, &h.BootID, &h.UptimeSeconds, &h.ClockOffsetSeconds, &h.Paused,
		&h.FactsDigest, &h.PolicyDigest, &h.SignersDigest,
		&h.Facts, &h.Policy, &h.Signers, &h.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if h.LastSeen.Unix() == 0 {
		h.LastSeen = time.Time{}
	}
	return h, wrap(err, "scanning a host")
}

// GetHost returns one host by id, or ErrNotFound.
func (s *scopedPostgres) GetHost(ctx context.Context, id string) (Host, error) {
	var h Host
	err := s.withTenant(ctx, "reading a host", func(tx pgx.Tx) error {
		var err error
		h, err = scanHost(tx.QueryRow(ctx,
			`SELECT `+hostColumns+` FROM hosts WHERE id = $1 AND tenant_id = $2`,
			id, string(s.tenant)))
		return err
	})
	if err != nil {
		return Host{}, err
	}
	return h, nil
}

// GetHostByMachineID returns the live host with a machine-id hash, or ErrNotFound.
//
// `NOT revoked` matches the partial unique index the schema puts on the same columns: a machine id is
// claimed by at most one host that has not been revoked, and revoking a host is therefore what
// releases its machine for re-enrolment without erasing the row an audit would want.
//
// The claim is per tenant, and so is this lookup. Across the installation it would be an oracle:
// enrolling a machine that belongs to somebody else would tell you that it belongs to somebody else.
func (s *scopedPostgres) GetHostByMachineID(ctx context.Context, hash string) (Host, error) {
	if hash == "" {
		return Host{}, ErrNotFound
	}
	var h Host
	err := s.withTenant(ctx, "reading a host by machine id", func(tx pgx.Tx) error {
		var err error
		h, err = scanHost(tx.QueryRow(ctx, `SELECT `+hostColumns+`
			  FROM hosts
			 WHERE machine_id_hash = $1 AND tenant_id = $2 AND NOT revoked`,
			hash, string(s.tenant)))
		return err
	})
	if err != nil {
		return Host{}, err
	}
	return h, nil
}

// CountHosts returns how many hosts this tenant has, without returning any of them.
//
// One statement and two integers. It is scoped through withTenant like every other read of a
// tenant-owned table, so the row-level security policy answers it rather than being worked around — a
// count taken outside the boundary would be the one query in this file that could see across it.
//
// `revoked` is counted rather than filtered so that both numbers come from one pass. The distinction
// matters to both callers: a host limit is checked against the active count, because revoking a host is
// how an operator makes room for another one, and a hosting provider bills the active count for the
// same reason.
func (s *scopedPostgres) CountHosts(ctx context.Context) (HostCounts, error) {
	var counts HostCounts
	err := s.withTenant(ctx, "counting hosts", func(tx pgx.Tx) error {
		return wrap(tx.QueryRow(ctx, `
			SELECT count(*), count(*) FILTER (WHERE NOT revoked)
			  FROM hosts
			 WHERE tenant_id = $1`,
			string(s.tenant)).Scan(&counts.Total, &counts.Active), "counting hosts")
	})
	if err != nil {
		return HostCounts{}, err
	}
	return counts, nil
}

// ListHosts returns every host in this tenant, ordered by hostname then id.
//
// The secondary sort on id matters: hostnames are not unique, and an unstable order makes the fleet
// list reshuffle between page loads for no reason a reader can see.
func (s *scopedPostgres) ListHosts(ctx context.Context) ([]Host, error) {
	var out []Host
	err := s.withTenant(ctx, "listing hosts", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+hostColumns+` FROM hosts WHERE tenant_id = $1 ORDER BY hostname, id`,
			string(s.tenant))
		if err != nil {
			return wrap(err, "listing hosts")
		}
		defer rows.Close()

		for rows.Next() {
			h, err := scanHost(rows)
			if err != nil {
				return err
			}
			out = append(out, h)
		}
		return wrap(rows.Err(), "listing hosts")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordHeartbeat applies a heartbeat's fields to a host.
//
// Only the columns a heartbeat carries are written. Updating the whole row would let a heartbeat
// overwrite the enrolment group or the stored facts document with a zero value, which is the kind of
// bug that shows up as data quietly disappearing.
//
// The digest columns are not among them, deliberately: they record what the server holds and are
// written only when a document arrives. See the note beside HeartbeatUpdate.
func (s *scopedPostgres) RecordHeartbeat(ctx context.Context, hostID string, u HeartbeatUpdate) error {
	return s.withTenant(ctx, "recording a heartbeat", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE hosts
			   SET agent_version = $3, boot_id = $4, uptime_seconds = $5, clock_offset_seconds = $6,
			       paused = $7, last_seen = $8
			 WHERE id = $1 AND tenant_id = $2`,
			hostID, string(s.tenant), u.AgentVersion, u.BootID, u.UptimeSeconds,
			u.ClockOffsetSeconds, u.Paused, u.LastSeen)
		if err != nil {
			return wrap(err, "recording a heartbeat")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// StoreFacts records a full facts document and its digest.
func (s *scopedPostgres) StoreFacts(ctx context.Context, hostID, digest string, document []byte) error {
	return s.storeDocument(ctx, hostID, "facts", "facts_digest", digest, document)
}

// StorePolicy records a host's effective policy and its digest.
func (s *scopedPostgres) StorePolicy(ctx context.Context, hostID, digest string, document []byte) error {
	return s.storeDocument(ctx, hostID, "policy", "policy_digest", digest, document)
}

// StoreSigners records a host's trusted key identities and their digest.
func (s *scopedPostgres) StoreSigners(ctx context.Context, hostID, digest string, document []byte) error {
	return s.storeDocument(ctx, hostID, "signers", "signers_digest", digest, document)
}

// storeDocument writes one JSONB column and its digest.
//
// The column names come from the three call sites above and never from anything external, which is why
// interpolating them into the statement is safe here and would not be anywhere a value is involved.
func (s *scopedPostgres) storeDocument(ctx context.Context, hostID, column, digestColumn, digest string, document []byte) error {
	if !json.Valid(document) {
		return fmt.Errorf("store: %s document for host %s is not valid JSON", column, hostID)
	}
	stmt := fmt.Sprintf(
		`UPDATE hosts SET %s = $3, %s = $4 WHERE id = $1 AND tenant_id = $2`, column, digestColumn)
	return s.withTenant(ctx, "storing a "+column+" document", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, stmt, hostID, string(s.tenant), document, digest)
		if err != nil {
			return wrap(err, "storing a "+column+" document")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// AddCertificate records an issued certificate by fingerprint.
//
// DO NOTHING on a fingerprint that is already recorded, because re-recording one is what a retried
// renewal does and it is not an error. The tenant written is this handle's, for the same reason
// CreateEnrolledHost writes it.
func (s *scopedPostgres) AddCertificate(ctx context.Context, c Certificate) error {
	return s.withTenant(ctx, "recording a certificate", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO certificates (fingerprint, host_id, tenant_id, serial, issued_at, not_after)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (fingerprint) DO NOTHING`,
			c.Fingerprint, c.HostID, string(s.tenant), c.Serial, c.IssuedAt, c.NotAfter)
		return wrap(err, "recording a certificate")
	})
}

// SupersedeCertificate sets when a renewed-away certificate stops being accepted.
//
// COALESCE keeps the earliest time rather than the latest, which is what makes a second renewal unable
// to extend the life of a credential the first one already replaced. Setting it on a certificate that
// is not this tenant's does nothing, because the policy admits no such row — the WHERE clause is the
// optimisation and the policy is the rule.
func (s *scopedPostgres) SupersedeCertificate(ctx context.Context, fingerprint string, at time.Time) error {
	return s.withTenant(ctx, "superseding a certificate", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE certificates
			   SET superseded_at = LEAST(COALESCE(superseded_at, $2::timestamptz), $2::timestamptz)
			 WHERE fingerprint = $1 AND tenant_id = $3`,
			fingerprint, at, string(s.tenant))
		return wrap(err, "superseding a certificate")
	})
}

// RenewCertificate admits a replacement certificate and retires the one that asked for it.
//
// The lock is a row lock on the host, taken first. It is the host that is being renewed, it is a row
// that exists by construction — requireAgent loaded it to get here — and locking it serialises every
// renewal for that host across every replica, which is what makes the count below a decision rather
// than a guess. An advisory lock on a hash of the id would do the same thing and would add a number to
// keep and a collision to reason about.
//
// The count and both writes are inside that lock and inside one transaction, so the outcomes are: the
// cap refuses and nothing is written, or the replacement is recorded and the presented certificate is
// retired together. There is no third state in which a host holds a credential the control plane has
// forgotten to retire.
func (s *scopedPostgres) RenewCertificate(ctx context.Context, r Renewal) error {
	return s.withTenant(ctx, "renewing a certificate", func(tx pgx.Tx) error {
		var locked string
		err := tx.QueryRow(ctx,
			`SELECT id FROM hosts WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
			r.Replacement.HostID, string(s.tenant)).Scan(&locked)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return wrap(err, "locking the host to renew it")
		}

		var live int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM certificates
			 WHERE host_id = $1 AND tenant_id = $2
			   AND NOT revoked
			   AND not_after > $3
			   AND (superseded_at IS NULL OR superseded_at > $3)`,
			r.Replacement.HostID, string(s.tenant), r.Now).Scan(&live); err != nil {
			return wrap(err, "counting live certificates")
		}
		if live >= r.MaxLive {
			return ErrTooManyCertificates
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO certificates (fingerprint, host_id, tenant_id, serial, issued_at, not_after)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (fingerprint) DO NOTHING`,
			r.Replacement.Fingerprint, r.Replacement.HostID, string(s.tenant),
			r.Replacement.Serial, r.Replacement.IssuedAt, r.Replacement.NotAfter); err != nil {
			return wrap(err, "recording the replacement certificate")
		}

		// LEAST keeps the earlier time, so a host renewing twice in quick succession cannot push back
		// the moment the credential it already replaced stops working.
		if _, err := tx.Exec(ctx, `
			UPDATE certificates
			   SET superseded_at = LEAST(COALESCE(superseded_at, $2::timestamptz), $2::timestamptz)
			 WHERE fingerprint = $1 AND tenant_id = $3`,
			r.Presented, r.SupersedeAt, string(s.tenant)); err != nil {
			return wrap(err, "retiring the presented certificate")
		}
		return nil
	})
}

// CountLiveCertificates returns how many of a host's certificates could still authenticate.
//
// The three conditions are the three requireAgent applies, which is why they are written out here
// rather than approximated: a count that disagreed with the middleware would produce a cap that either
// refused a host with one working certificate or admitted one with twenty.
func (s *scopedPostgres) CountLiveCertificates(ctx context.Context, hostID string, now time.Time) (int, error) {
	var live int
	err := s.withTenant(ctx, "counting live certificates", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM certificates
			 WHERE host_id = $1 AND tenant_id = $2
			   AND NOT revoked
			   AND not_after > $3
			   AND (superseded_at IS NULL OR superseded_at > $3)`,
			hostID, string(s.tenant), now).Scan(&live)
	})
	return live, err
}

// RevokeHost marks a host and all its certificates as revoked.
//
// Both happen in one transaction, because a host marked revoked whose certificates were not would keep
// authenticating, and certificates revoked without the host would leave a host that could re-enrol.
func (s *scopedPostgres) RevokeHost(ctx context.Context, hostID string) error {
	return s.withTenant(ctx, "revoking a host", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE hosts SET revoked = true WHERE id = $1 AND tenant_id = $2`,
			hostID, string(s.tenant))
		if err != nil {
			return wrap(err, "revoking a host")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `
			UPDATE certificates
			   SET revoked = true, revoked_at = now()
			 WHERE host_id = $1 AND tenant_id = $2`,
			hostID, string(s.tenant),
		); err != nil {
			return wrap(err, "revoking a host's certificates")
		}
		return nil
	})
}

// DeleteHost removes a host and everything that references it.
//
// The dependent rows go with it through the schema's ON DELETE CASCADE rather than through statements
// here, so that a table added later cannot be forgotten by this function.
func (s *scopedPostgres) DeleteHost(ctx context.Context, hostID string) error {
	return s.withTenant(ctx, "deleting a host", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM hosts WHERE id = $1 AND tenant_id = $2`,
			hostID, string(s.tenant))
		if err != nil {
			return wrap(err, "deleting a host")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// CreateJob records a job and lets the trigger wake whichever agent is waiting for it.
//
// The insert is the whole operation: the NOTIFY comes from a trigger on the table rather than from
// here, so a job inserted by any path — this, a maintenance script, a future scheduler — wakes the
// agent that is waiting for it. See 0001_initial.sql.
//
// Both halves of the approval rule are written as the caller decided them, not derived here. What the
// tenant's mode said at creation is what this job needs for ever after: an operator who queues a job
// under the two-person rule and then relaxes the setting must not find they may now release it
// themselves.
func (s *scopedPostgres) CreateJob(ctx context.Context, j NewJob) error {
	params, err := json.Marshal(j.Job.Params)
	if err != nil {
		return fmt.Errorf("store: encoding job parameters: %w", err)
	}
	if j.Job.Params == nil {
		params = []byte("{}")
	}

	return s.withTenant(ctx, "creating a job", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO jobs (id, tenant_id, host_id, intent, params, class, issued_at, not_before,
			                  not_after, nonce, signature, signer_key_id, signer_algorithm,
			                  created_by, approval_required, approval_distinct_operator)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			        NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''), $14, $15, $16)`,
			j.Job.ID, string(s.tenant), j.HostID, j.Job.Intent, params, j.Job.Class,
			j.Job.IssuedAt, j.Job.NotBefore, j.Job.NotAfter, j.Job.Nonce,
			j.Job.Signature, j.Job.SignerKeyID, j.Job.SignerAlgorithm,
			j.CreatedBy, j.ApprovalRequired, j.ApprovalDistinctOperator)
		// A foreign-key violation here means one thing only: no such host in this tenant. It is
		// translated locally rather than in wrap, because for every other insert in this file an FK
		// violation is an internal bug and reporting it as "not found" would send somebody looking for
		// a missing row that was never the problem.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrNotFound
		}
		// wrap turns a unique violation into ErrConflict, which here is either a job id already taken
		// in this tenant — the primary key is (tenant_id, id) — or a signed nonce already queued for
		// this host.
		return wrap(err, "creating a job")
	})
}

// ApproveJob records an operator's release of a job.
//
// The rules are in the WHERE clause rather than in a read followed by a write, and that placement is
// the point: two requests arriving at once must not let the same operator release their own job by
// racing it against itself. The caller reads the row first to produce a good error message; this is
// what decides.
//
// Whether the releaser may be the creator is read from the job's own row, not from the tenant's
// current setting, so that a mode relaxed after the job was queued cannot release it. Keeping that
// condition inside the statement is what keeps it atomic — hoisting it into Go would reinstate exactly
// the race the placement exists to close.
func (s *scopedPostgres) ApproveJob(ctx context.Context, jobID, approver string, now time.Time) error {
	return s.withTenant(ctx, "approving a job", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE jobs
			   SET approved_at = $4, approved_by = $3
			 WHERE id = $1
			   AND tenant_id = $2
			   AND approval_required
			   AND approved_at IS NULL
			   AND (NOT approval_distinct_operator OR created_by <> $3)`,
			jobID, string(s.tenant), approver, now)
		if err != nil {
			return wrap(err, "approving a job")
		}
		if tag.RowsAffected() > 0 {
			return nil
		}
		// Nothing moved, and the two reasons want different answers: a job that does not exist is a 404
		// and a job that cannot be approved is a 409. The distinction is drawn with a second query
		// rather than by relaxing the update's WHERE clause, so the rules above stay atomic — this runs
		// only on the failure path and only to choose an error.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM jobs WHERE id = $1 AND tenant_id = $2)`,
			jobID, string(s.tenant)).Scan(&exists); err != nil {
			return wrap(err, "approving a job")
		}
		if !exists {
			return ErrNotFound
		}
		return ErrConflict
	})
}

// jobColumns is the projection every job read shares.
//
// Written once because the three readers must agree about what a job record contains: a column added to
// one query and forgotten in another produces a record that is complete on one screen and missing a
// field on the next, which reads as a bug in the UI.
const jobColumns = `j.id, j.host_id, j.intent, j.params, j.class, j.issued_at, j.not_before,
	j.not_after, j.nonce, COALESCE(j.signature, ''), COALESCE(j.signer_key_id, ''),
	COALESCE(j.signer_algorithm, ''), j.created_by, j.approval_required,
	j.approval_distinct_operator, j.approved_at,
	j.approved_by, j.claimed_at, j.completed_at,
	r.status, r.started_at, r.finished_at, r.exit_code, r.output, r.output_truncated, r.result, r.error`

// scanJob reads one row of jobColumns into a record.
func scanJob(row pgx.Row) (JobRecord, error) {
	var rec JobRecord
	var approvedAt, claimedAt, completedAt *time.Time
	var status, output, errText *string
	var startedAt, finishedAt *time.Time
	var exitCode *int
	var outputTruncated *bool
	var resultJSON []byte

	if err := row.Scan(&rec.Job.ID, &rec.HostID, &rec.Job.Intent, &rec.Job.Params, &rec.Job.Class,
		&rec.Job.IssuedAt, &rec.Job.NotBefore, &rec.Job.NotAfter, &rec.Job.Nonce,
		&rec.Job.Signature, &rec.Job.SignerKeyID, &rec.Job.SignerAlgorithm,
		&rec.CreatedBy, &rec.ApprovalRequired, &rec.ApprovalDistinctOperator, &approvedAt,
		&rec.ApprovedBy, &claimedAt, &completedAt,
		&status, &startedAt, &finishedAt, &exitCode, &output, &outputTruncated, &resultJSON,
		&errText); err != nil {
		return JobRecord{}, err
	}

	rec.CreatedAt = rec.Job.IssuedAt
	for _, pair := range []struct {
		src *time.Time
		dst *time.Time
	}{{approvedAt, &rec.ApprovedAt}, {claimedAt, &rec.ClaimedAt}, {completedAt, &rec.CompletedAt}} {
		if pair.src != nil {
			*pair.dst = *pair.src
		}
	}

	// A result row is present only once a host has reported. The LEFT JOIN yields nulls until then, and
	// a nil Result is how a caller tells "not reported yet" from "reported nothing", which are
	// different states an operator needs distinguished.
	if status != nil {
		result := protocol.ResultRequest{JobID: rec.Job.ID, Status: *status}
		if startedAt != nil {
			result.StartedAt = *startedAt
		}
		if finishedAt != nil {
			result.FinishedAt = *finishedAt
		}
		if exitCode != nil {
			result.ExitCode = *exitCode
		}
		if output != nil {
			result.Output = *output
		}
		if outputTruncated != nil {
			result.OutputTruncated = *outputTruncated
		}
		if errText != nil {
			result.Error = *errText
		}
		if len(resultJSON) > 0 && string(resultJSON) != "null" {
			var decoded any
			if err := json.Unmarshal(resultJSON, &decoded); err == nil {
				result.Result = decoded
			}
		}
		rec.Result = &result
	}
	return rec, nil
}

// ListJobs returns jobs newest first, with their results.
//
// The tenant predicate is here as well as in the policy, and it is the half that makes the listing
// fast: it is the leading column of the three indexes migration 0004 adds, and without it the planner
// has nothing to seek on and sorts the tenant's whole history to return a page of it.
func (s *scopedPostgres) ListJobs(ctx context.Context, f JobFilter) ([]JobRecord, error) {
	limit := clampJobLimit(f.Limit)
	out := make([]JobRecord, 0, limit)
	err := s.withTenant(ctx, "listing jobs", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+jobColumns+`
			  FROM jobs j
			  LEFT JOIN job_results r ON r.tenant_id = j.tenant_id AND r.job_id = j.id
			 WHERE j.tenant_id = $4
			   AND ($1 = '' OR j.host_id = $1)
			   AND (NOT $3::boolean OR (j.approval_required AND j.approved_at IS NULL))
			 -- By creation time, not by id. Ids are lexically sortable only when this control plane
			 -- generated them; a signed job's id comes from whoever signed it and can be any string, so
			 -- ordering by it would file a queued reboot wherever its id happened to fall — possibly off
			 -- the end of the page the second operator reads before approving it. The id breaks ties so
			 -- the order is total, and so two implementations can agree on it.
			 ORDER BY j.issued_at DESC, j.id DESC
			 LIMIT $2`, f.HostID, limit, f.AwaitingApproval, string(s.tenant))
		if err != nil {
			return wrap(err, "listing jobs")
		}
		defer rows.Close()

		for rows.Next() {
			rec, err := scanJob(rows)
			if err != nil {
				return wrap(err, "scanning a job")
			}
			out = append(out, rec)
		}
		return wrap(rows.Err(), "listing jobs")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetJob returns one job and its result, or ErrNotFound.
//
// A job is identified by its tenant and its id together, because that is what the primary key became:
// a signed job's id is chosen by whoever signed it, and two customers picking "reboot-2026-08-23" on
// the same day is an ordinary thing rather than a collision.
func (s *scopedPostgres) GetJob(ctx context.Context, jobID string) (JobRecord, error) {
	var rec JobRecord
	err := s.withTenant(ctx, "reading a job", func(tx pgx.Tx) error {
		var err error
		rec, err = scanJob(tx.QueryRow(ctx, `
			SELECT `+jobColumns+`
			  FROM jobs j
			  LEFT JOIN job_results r ON r.tenant_id = j.tenant_id AND r.job_id = j.id
			 WHERE j.id = $1 AND j.tenant_id = $2`, jobID, string(s.tenant)))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return wrap(err, "reading a job")
	})
	if err != nil {
		return JobRecord{}, err
	}
	return rec, nil
}

// ClaimJobs atomically takes up to limit jobs for a host.
//
// FOR UPDATE SKIP LOCKED against the partial index is what lets the control plane run more than one
// replica: two instances claiming for the same host at the same moment take disjoint rows rather than
// blocking or double-delivering.
func (s *scopedPostgres) ClaimJobs(ctx context.Context, hostID string, limit int) ([]protocol.Job, error) {
	if limit <= 0 {
		limit = 10
	}
	var out []protocol.Job
	err := s.withTenant(ctx, "claiming jobs", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH claimed AS (
				SELECT id FROM jobs
				 WHERE tenant_id = $3 AND host_id = $1
				   AND claimed_at IS NULL AND completed_at IS NULL
				   -- A job still waiting for its second operator is not work this host may take. The
				   -- condition is here rather than in the handler because the handler is not the only
				   -- thing that will ever claim.
				   AND (NOT approval_required OR approved_at IS NOT NULL)
				   -- Nor is a job whose window has not opened. Handing one over early does not delay
				   -- it, it destroys it: the agent checks the window, finds it shut, and reports that
				   -- as a terminal status, so a maintenance window signed for Sunday would be burned
				   -- on Thursday and could never run.
				   --
				   -- This is a delivery decision taken on the server's clock and it is deliberately
				   -- NOT the authorisation check. The agent re-checks the window against its own
				   -- clock, which is the only clock allowed to decide whether a signed job may run —
				   -- a control plane that lied here could withhold work, which it can do anyway, but
				   -- could never extend a signature's validity. See docs/SECURITY.md §4.3.
				   AND not_before <= now()
				 ORDER BY issued_at
				 LIMIT $2
				 FOR UPDATE SKIP LOCKED
			)
			UPDATE jobs SET claimed_at = now()
			 WHERE tenant_id = $3 AND id IN (SELECT id FROM claimed)
			RETURNING id, intent, params, class, issued_at, not_before, not_after, nonce,
			          COALESCE(signature, ''), COALESCE(signer_key_id, ''),
			          COALESCE(signer_algorithm, '')`,
			hostID, limit, string(s.tenant))
		if err != nil {
			return wrap(err, "claiming jobs")
		}
		defer rows.Close()

		for rows.Next() {
			var j protocol.Job
			if err := rows.Scan(&j.ID, &j.Intent, &j.Params, &j.Class, &j.IssuedAt,
				&j.NotBefore, &j.NotAfter, &j.Nonce,
				&j.Signature, &j.SignerKeyID, &j.SignerAlgorithm); err != nil {
				return wrap(err, "scanning a claimed job")
			}
			out = append(out, j)
		}
		return wrap(rows.Err(), "claiming jobs")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordResult stores a job result idempotently, for a job that belongs to the reporting host.
func (s *scopedPostgres) RecordResult(ctx context.Context, hostID string, r protocol.ResultRequest) (bool, error) {
	resultJSON := []byte("null")
	if r.Result != nil {
		encoded, err := json.Marshal(r.Result)
		if err != nil {
			return false, fmt.Errorf("store: encoding a job result: %w", err)
		}
		resultJSON = encoded
	}

	inserted := false
	err := s.withTenant(ctx, "recording a job result", func(tx pgx.Tx) error {
		// The job must belong to the reporting host. Every enrolled host is authenticated and none is
		// trusted: without this, any host could post a result for another host's job, and because
		// recording is idempotent the forged result would then suppress the real one when it arrived.
		//
		// It must also have been claimed. A result for work this host was never given is not a result:
		// without that condition a compromised host could complete a destructive job still waiting for
		// its second operator, which sets completed_at and excludes the row from the claim for ever —
		// and it could not be re-queued either, because the partial unique index has taken its signed
		// nonce. The dashboard would show "succeeded" for work nobody authorised, let alone performed.
		var owned bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1 FROM jobs
			     WHERE id = $1 AND tenant_id = $2 AND host_id = $3 AND claimed_at IS NOT NULL
			)`, r.JobID, string(s.tenant), hostID,
		).Scan(&owned); err != nil {
			return wrap(err, "checking job ownership")
		}
		if !owned {
			return ErrNotFound
		}

		// DO NOTHING rather than DO UPDATE. A repeated result means the first response was lost, not
		// that the work happened twice, and overwriting would replace a genuine record with a retry's
		// view of it. The conflict target is the whole primary key, which is now the tenant and the job
		// together. The affected-row count is what answers "was this the first": zero means a record
		// already stood, which is the retry the caller must not notify about again.
		tag, err := tx.Exec(ctx, `
			INSERT INTO job_results (job_id, tenant_id, host_id, status, started_at, finished_at,
			                         exit_code, output, output_truncated, result, error)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (tenant_id, job_id) DO NOTHING`,
			r.JobID, string(s.tenant), hostID, r.Status, r.StartedAt, r.FinishedAt, r.ExitCode,
			r.Output, r.OutputTruncated, resultJSON, r.Error,
		)
		if err != nil {
			return wrap(err, "recording a job result")
		}
		inserted = tag.RowsAffected() > 0
		if _, err := tx.Exec(ctx, `
			UPDATE jobs
			   SET completed_at = COALESCE(completed_at, now())
			 WHERE id = $1 AND tenant_id = $2 AND host_id = $3`,
			r.JobID, string(s.tenant), hostID,
		); err != nil {
			return wrap(err, "completing a job")
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// Subscribe registers interest in work for a host and returns a channel closed when some arrives.
//
// One connection LISTENs for the whole process and fans notifications out in memory. A design that
// opened a connection per waiting agent would need five hundred PostgreSQL connections to hold five
// hundred long-polls, which is more than most instances allow in total — so the fan-out is what makes
// the long-poll affordable at fleet scale.
func (p *Postgres) Subscribe(hostID string) (<-chan struct{}, func()) {
	p.listenerOnce.Do(func() { go p.listen() })

	wake := make(chan struct{})
	p.mu.Lock()
	p.waiters[hostID] = append(p.waiters[hostID], wake)
	p.mu.Unlock()

	return wake, func() { p.removeWaiter(hostID, wake) }
}

// removeWaiter drops a waiter, whether it was woken or gave up.
//
// Without it, a fleet whose agents time out and reconnect every twenty-five seconds would accumulate
// dead channels for the process's lifetime — a slow leak that only shows up after a week of uptime,
// which is the worst kind. It is idempotent, because the caller always releases its subscription and
// the waker has usually already removed it.
func (p *Postgres) removeWaiter(hostID string, wake chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	waiters := p.waiters[hostID]
	for i, w := range waiters {
		if w == wake {
			p.waiters[hostID] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(p.waiters[hostID]) == 0 {
		delete(p.waiters, hostID)
	}
}

// listen holds the single LISTEN connection and wakes waiters.
//
// It reconnects with backoff rather than exiting. Losing the listener silently would turn every
// long-poll into a plain twenty-five-second poll: still correct, still functional, and slower in a way
// nobody would notice until they wondered why jobs took half a minute to start.
func (p *Postgres) listen() {
	backoff := time.Second
	for {
		select {
		case <-p.closed:
			return
		default:
		}

		if err := p.listenOnce(); err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			slog.Error("job notification listener failed; retrying",
				"error", err, "retry_in", backoff)
			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

// listenOnce opens a dedicated connection, LISTENs, and relays notifications until it fails.
func (p *Postgres) listenOnce() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-p.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	conn, err := pgx.Connect(ctx, p.dsn)
	if err != nil {
		return fmt.Errorf("store: connecting the listener: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if _, err := conn.Exec(ctx, "LISTEN "+jobChannel); err != nil {
		return fmt.Errorf("store: LISTEN %s: %w", jobChannel, err)
	}
	p.readyOnce.Do(func() { close(p.ready) })

	// Deliberately *not* waking every waiter here.
	//
	// Doing so would close the gap in which a job was inserted while the listener was down, at the cost
	// of waking every long-poll in the fleet at the same instant — five hundred agents all re-reading
	// the job queue in the same moment, immediately after a database that has just recovered. The gap
	// it closes is bounded and small: an agent whose long-poll is not woken returns empty after its
	// hold expires and polls again, so a job inserted during a listener outage starts at most one poll
	// interval late. Twenty-five seconds of extra latency in a rare failure is a much better trade than
	// a synchronised burst at exactly the wrong moment.

	for {
		notification, err := conn.WaitForNotification(ctx)
		if err != nil {
			return fmt.Errorf("store: waiting for a notification: %w", err)
		}
		p.wake(notification.Payload)
	}
}

// wake releases the waiters for one host.
func (p *Postgres) wake(hostID string) {
	p.mu.Lock()
	waiters := p.waiters[hostID]
	delete(p.waiters, hostID)
	p.mu.Unlock()

	for _, w := range waiters {
		close(w)
	}
}

// wrap adds context to a database error, translating the ones callers switch on.
//
// Unique-violation becomes ErrConflict so that handlers can return 409 without matching on a driver
// string, which is how a PostgreSQL upgrade turns a 409 into a 500.
func wrap(err error, what string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %s", ErrConflict, what)
	}
	return fmt.Errorf("store: %s: %w", what, err)
}
