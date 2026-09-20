package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pascalgross/hostseal/internal/protocol"
)

// DefaultTenant is the tenant a fresh store already contains.
//
// Migration 0004 inserts exactly this row, so a migrated database has it before anything else runs. The
// in-memory store seeds the same one because the alternative diverges at the least visible moment: a
// `hostseal-server serve --store memory` process, and every server test, would begin with no tenant at
// all and fail on the first scoped write in a way the shipped store never does.
const DefaultTenant TenantID = "default"

// jobKey identifies one job the way the schema does, by tenant and id together.
//
// It is migration 0004's composite primary key expressed as a map key, and the reason is the same one
// the migration gives: a signed job's id comes from the customer's offline signer and is theirs to
// choose, so two tenants queueing "reboot-2026-08-23" on the same day is ordinary rather than a
// collision. Keyed on the id alone, the second one would overwrite the first: one customer's reboot
// silently replaced by another's, which is a cross-tenant write in the most literal sense.
type jobKey struct {
	// tenant owns the job.
	tenant TenantID

	// id is the job's own identifier, as its signer or the control plane chose it.
	id string
}

// queueKey identifies one host's pending queue, by tenant and host id together.
//
// The tenant belongs in the key rather than in a check the caller remembers to make: claiming against a
// host id that belongs to somebody else then reads an empty queue instead of another tenant's work,
// which is the answer row-level security gives and for the same reason — the identifier does not match.
type queueKey struct {
	// tenant owns the host whose queue this is.
	tenant TenantID

	// host is the host id the work is addressed to.
	host string
}

// hostRow is a host together with the tenant that owns it.
//
// Host itself carries no tenant, because nothing outside the store has any business choosing one — the
// tenant comes from the handle the caller had to obtain. It has to be recorded somewhere all the same,
// since every read filters on it, so it is kept beside the record rather than inside it.
type hostRow struct {
	// host is the record as callers see it.
	host Host

	// tenant is the fleet it belongs to.
	tenant TenantID
}

// tokenRow is an enrolment token together with the tenant that issued it.
//
// Keyed by hash alone, like the table: a token hash is a SHA-256 of 256 bits of randomness, so it is
// globally unique in the only sense that matters and the tenant is what the hash resolves *to*. That
// resolution is why TenantForEnrollmentToken can run before any tenant is known.
type tokenRow struct {
	// token is the record as callers see it.
	token EnrollmentToken

	// tenant is the fleet a host enrolling with it joins.
	tenant TenantID
}

// Memory is an in-memory Store.
//
// It exists so tests do not need a database, and so `hostseal-server serve --store memory` can run a
// demonstration or an integration harness without one. It is **not** a supported production backend and
// the server logs loudly when it is used: everything is lost on restart, nothing is shared between
// replicas, and none of the PostgreSQL properties the real store depends on — atomic claiming, GIN
// indexes on facts, LISTEN/NOTIFY — is really being exercised.
//
// Keeping it honest matters more than keeping it complete: where a behaviour here differs from
// PostgreSQL in a way a caller could notice, the difference is written down at the method rather than
// papered over, so that a test passing against Memory is not mistaken for a test passing.
//
// Tenancy is modelled with composite keys inside one store rather than with a separate Memory per
// tenant, and that is the same principle rather than an implementation detail. A store that physically
// could not mix two tenants would make every isolation test in internal/server pass by construction,
// including the ones written against a boundary that had been removed. This store can get isolation
// wrong. That is what makes asserting it worth anything.
type Memory struct {
	// mu guards every field below. One lock for the whole store is right here: the memory store exists
	// for tests, where contention is irrelevant and a single obvious lock is worth more than
	// throughput.
	mu sync.Mutex

	// tenants are the fleets themselves, by id. Not scoped to anything: a row here *is* a tenant.
	tenants map[TenantID]Tenant

	// tokens are enrolment tokens by hash, each carrying the tenant it was issued for.
	tokens map[string]tokenRow

	// hosts are enrolled hosts by id, each carrying the tenant it belongs to.
	//
	// Keyed by id alone because the schema's primary key is still the id alone: a host id is generated
	// here from 128 bits of randomness, and two tenants cannot hold the same one. The composite unique
	// constraint added in 0004 is what the foreign keys point at, not a licence to reuse an id.
	hosts map[string]hostRow

	// certs are issued certificates by fingerprint. Certificate carries its own tenant, because
	// resolving a fingerprint to one is how an agent request discovers who it is.
	certs map[string]Certificate

	// jobs are pending jobs by tenant and host, in delivery order.
	jobs map[queueKey][]protocol.Job

	// records are every job ever created, by tenant and id, whether or not it has been claimed.
	//
	// It is separate from `jobs` because the two answer different questions: `jobs` is the queue and is
	// emptied on claim, and this is the history the API and the UI read. Keeping one map and filtering
	// would mean a claimed job vanished from the operator's view at the moment it became interesting.
	//
	// It is also what a result is checked against, so a job's host outlives the queue entry: a forged
	// result arrives after the claim, when the queue no longer remembers anything.
	records map[jobKey]JobRecord

	// results are recorded results by tenant and job id, which is what makes recording idempotent.
	results map[jobKey]protocol.ResultRequest

	// waiters are channels to wake per host, standing in for LISTEN/NOTIFY.
	//
	// Keyed by host id and not by tenant, matching Store.Subscribe: a wake-up carries no data, and the
	// host id it is keyed on is 128 bits of randomness. The work itself is behind the claim, which is
	// scoped.
	waiters map[string][]chan struct{}

	// templates are provisioning template versions by tenant, name and version, immutable once written.
	templates map[templateKey]TemplateVersion

	// events is every tenant's inbox, oldest first, evicted per tenant past MaxEventsPerTenant.
	events []eventRow

	// transitions is unit-state history, oldest first, evicted per host past
	// MaxUnitTransitionsPerHost.
	transitions []transitionRow

	// rules are alert rules by tenant and id.
	rules map[ruleKey]AlertRule

	// states are the alert evaluator's memory by tenant, rule and host.
	states map[stateKey]AlertState

	// accounts are accounts by id, each carrying the tenant it belongs to — or none, for a platform one.
	//
	// Keyed by the id alone, matching the primary key migration 0010 moved it to: an account id is 128
	// bits generated here, so it is unique across the installation by construction and a session can
	// point at one without carrying a tenant it has no business knowing.
	accounts map[string]Account

	// sessions are signed-in browsers by the SHA-256 of their token.
	//
	// Keyed by the hash alone, matching the schema and matching how the row is reached: resolving a
	// token is how a request discovers whose it is, so anything else in the key would be something the
	// caller does not yet have.
	sessions map[string]Session

	// apiTokens are the credentials scripts present, by the SHA-256 of the token.
	apiTokens map[string]APIToken

	// shares are published wallboard links by id, each carrying the tenant whose screen it publishes.
	//
	// Keyed by the id alone rather than by (tenant, id), for the reason hosts are: a share id is 128
	// bits generated by the control plane, so two fleets cannot hold the same one, and the schema's
	// composite primary key is what the tenant column is *for* rather than a licence to reuse an id.
	shares map[string]wallboardShareRow
}

// NewMemory returns an in-memory store holding the default tenant and nothing else.
//
// The tenant is seeded rather than left to the caller because Migrate does nothing here while the real
// Migrate inserts it — see DefaultTenant. A store that started empty would make the first scoped write
// fail on a store nobody had "migrated", which is a difference between the two backends that no test
// asserts and every caller would trip over.
func NewMemory() *Memory {
	return &Memory{
		tenants: map[TenantID]Tenant{
			DefaultTenant: {
				ID:           DefaultTenant,
				Slug:         "default",
				DisplayName:  "Default",
				CreatedAt:    time.Now().UTC(),
				ApprovalMode: ApprovalNone,
			},
		},
		tokens:    map[string]tokenRow{},
		hosts:     map[string]hostRow{},
		certs:     map[string]Certificate{},
		jobs:      map[queueKey][]protocol.Job{},
		records:   map[jobKey]JobRecord{},
		results:   map[jobKey]protocol.ResultRequest{},
		waiters:   map[string][]chan struct{}{},
		templates: map[templateKey]TemplateVersion{},
		rules:     map[ruleKey]AlertRule{},
		states:    map[stateKey]AlertState{},
		accounts:  map[string]Account{},
		sessions:  map[string]Session{},
		apiTokens: map[string]APIToken{},
		shares:    map[string]wallboardShareRow{},
	}
}

// Migrate does nothing; an empty map is already up to date, and NewMemory seeded the default tenant.
func (m *Memory) Migrate(_ context.Context) error { return nil }

// Ping always succeeds; the store is this process's memory, so it is reachable whenever this is.
func (m *Memory) Ping(_ context.Context) error { return nil }

// Close does nothing; there is nothing to release.
func (m *Memory) Close() error { return nil }

// In returns a handle on one tenant's data.
//
// It does not check that the tenant exists, and cannot usefully: it returns no error, and PostgreSQL's
// equivalent — setting hostseal.tenant on a transaction — does not check either. An unknown tenant is
// discovered at the first operation, and discovered the same way in both stores: reads return nothing,
// and the writes the schema's foreign keys cover are refused.
func (m *Memory) In(tenant TenantID) Scoped {
	return &scopedMemory{store: m, tenant: tenant}
}

// errUnknownTenant reports a write naming a tenant that does not exist.
//
// It is a plain error rather than one of the package's sentinels because that is what the shipped store
// produces: the foreign key from hosts and enrollment_tokens to tenants raises a violation, which
// arrives as an unclassified error and not as ErrNotFound or ErrConflict. Returning a sentinel here
// would let a test assert against Memory something the database does not do.
func errUnknownTenant(tenant TenantID) error {
	return fmt.Errorf("store: no such tenant %q", tenant)
}

// normaliseApprovalMode applies the column's default and refuses what its CHECK constraint would.
//
// The empty mode is treated as the default rather than as a violation: a Go zero value means
// "unspecified", which is the case a column default exists to answer. Anything else that is not one of
// the three is refused here rather than stored, so that a mode nobody can act on cannot reach a job.
func normaliseApprovalMode(mode ApprovalMode) (ApprovalMode, error) {
	if mode == "" {
		return ApprovalNone, nil
	}
	if !mode.Valid() {
		return "", fmt.Errorf("store: unknown approval mode %q", mode)
	}
	return mode, nil
}

// CreateTenant records a new tenant.
//
// A repeated id or a slug somebody else already holds is ErrConflict, matching the primary key and the
// UNIQUE constraint on slug. A zero CreatedAt is filled in, as the column's default does, so that
// ListTenants has something to order by.
//
// An empty id is refused here too, matching both the PostgreSQL store's own guard and the
// tenants_id_nonempty constraint migration 0011 adds. The reason is a PostgreSQL one and does not
// apply to a map — but a store that accepted a value the other refuses would let a test pass here and
// fail there, which is the one thing an in-memory stand-in must not do.
func (m *Memory) CreateTenant(_ context.Context, t Tenant) error {
	if t.ID == "" {
		return errors.New("store: a tenant needs an id")
	}
	mode, err := normaliseApprovalMode(t.ApprovalMode)
	if err != nil {
		return err
	}
	t.ApprovalMode = mode

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[t.ID]; exists {
		return ErrConflict
	}
	for _, existing := range m.tenants {
		if existing.Slug == t.Slug {
			return ErrConflict
		}
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m.tenants[t.ID] = t
	return nil
}

// GetTenant returns one tenant, or ErrNotFound.
func (m *Memory) GetTenant(_ context.Context, id TenantID) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return t, nil
}

// ListTenants returns every tenant, oldest first.
//
// The id breaks ties, because two tenants created in the same instant is what a seeding script does and
// a listing that reshuffled between calls would make a test flake for a reason nobody would find.
func (m *Memory) ListTenants(_ context.Context) ([]Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// UpdateTenant applies a tenant's display name, approval mode, webhook URL, host limit and suspension.
//
// The id, the slug and the creation time are not editable: they are what other rows, URLs and support
// tickets refer to, and a customer changing what they are called must not change what they are.
//
// Nothing already queued is revisited. A job records the approval rule it was created under, so
// relaxing this setting cannot release work that was queued under a stricter one.
func (m *Memory) UpdateTenant(_ context.Context, id TenantID, patch TenantPatch) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}

	// Field by field, matching the PostgreSQL statement: only what the patch carries is written, so a
	// caller changing one setting cannot restore stale values for the others.
	if patch.DisplayName != nil {
		existing.DisplayName = *patch.DisplayName
	}
	if patch.ApprovalMode != nil {
		mode, err := normaliseApprovalMode(*patch.ApprovalMode)
		if err != nil {
			return Tenant{}, err
		}
		existing.ApprovalMode = mode
	}
	if patch.WebhookURL != nil {
		existing.WebhookURL = *patch.WebhookURL
	}
	if patch.SetHostLimit {
		existing.HostLimit = patch.HostLimit
	}
	if patch.Suspended != nil {
		existing.Suspended = *patch.Suspended
	}

	m.tenants[id] = existing
	return existing, nil
}

// DeleteTenant removes a tenant and everything belonging to it.
//
// Every map is swept rather than only the obvious ones, because this stands in for a cascade the
// database performs from a single DELETE. A record left behind here would be a row belonging to a
// tenant that no longer exists — reachable by whoever is given that id next, which is the one way a
// deletion can turn into a disclosure.
//
// Waiters are deliberately left alone. A subscription holds no data, its release function is what
// removes it, and closing channels out from under long-polls that are still running would trade a
// tidy map for a wake-up that means nothing.
func (m *Memory) DeleteTenant(_ context.Context, id TenantID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tenants[id]; !ok {
		return ErrNotFound
	}
	delete(m.tenants, id)

	for hash, row := range m.tokens {
		if row.tenant == id {
			delete(m.tokens, hash)
		}
	}
	for hostID, row := range m.hosts {
		if row.tenant == id {
			delete(m.hosts, hostID)
		}
	}
	for fingerprint, c := range m.certs {
		if c.TenantID == id {
			delete(m.certs, fingerprint)
		}
	}
	for key := range m.jobs {
		if key.tenant == id {
			delete(m.jobs, key)
		}
	}
	for key := range m.records {
		if key.tenant == id {
			delete(m.records, key)
		}
	}
	// Swept on its own key rather than through the records above, so that a result whose job had somehow
	// gone missing still leaves with its tenant. The two maps are written together and deleted together
	// everywhere else; a sweep that relied on that would be trusting an invariant to hold at exactly the
	// moment something has already gone wrong.
	for key := range m.results {
		if key.tenant == id {
			delete(m.results, key)
		}
	}
	for key := range m.templates {
		if key.tenant == id {
			delete(m.templates, key)
		}
	}
	keptEvents := m.events[:0]
	for _, row := range m.events {
		if row.tenant != id {
			keptEvents = append(keptEvents, row)
		}
	}
	m.events = keptEvents
	keptTransitions := m.transitions[:0]
	for _, row := range m.transitions {
		if row.tenant != id {
			keptTransitions = append(keptTransitions, row)
		}
	}
	m.transitions = keptTransitions
	for key := range m.rules {
		if key.tenant == id {
			delete(m.rules, key)
		}
	}
	for key := range m.states {
		if key.tenant == id {
			delete(m.states, key)
		}
	}
	// The published wallboard links, which are the sharpest instance of the reason this sweep exists:
	// a share left behind is a live public URL into a tenant id, and the fleet handed that id next
	// would be published to whoever still had the link — with nothing on either side to notice.
	for shareID, row := range m.shares {
		if row.tenant == id {
			delete(m.shares, shareID)
		}
	}
	// Accounts, and the sessions and tokens they hold. The database performs this from one DELETE
	// through a chain of ON DELETE CASCADEs; here it is three sweeps, and the credentials are swept on
	// the accounts that were removed rather than on the tenant, because a credential row carries no
	// tenant of its own since migration 0010.
	gone := map[string]bool{}
	for accountID, account := range m.accounts {
		if account.TenantID == id {
			gone[accountID] = true
			delete(m.accounts, accountID)
		}
	}
	for hash, held := range m.sessions {
		if gone[held.AccountID] {
			delete(m.sessions, hash)
		}
	}
	for hash, held := range m.apiTokens {
		if gone[held.AccountID] {
			delete(m.apiTokens, hash)
		}
	}
	return nil
}

// LookupCertificate returns a certificate by fingerprint, or ErrNotFound.
//
// Not scoped, like the interface says: this is how an agent request finds out which tenant it belongs
// to, so it cannot be behind a handle that requires already knowing.
func (m *Memory) LookupCertificate(_ context.Context, fingerprint string) (Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.certs[fingerprint]
	if !ok {
		return Certificate{}, ErrNotFound
	}
	return c, nil
}

// TenantForEnrollmentToken returns the tenant a token belongs to, or ErrTokenUnusable.
//
// Resolution is by hash and nothing else. An expired or already-consumed token still names its tenant,
// because refusing here would decide the enrolment before ConsumeEnrollmentToken — the one place that
// can refuse it atomically — had been asked, and a host retrying an enrolment it already completed
// would be told no by a check that cannot tell it apart from an attacker's guess anyway.
func (m *Memory) TenantForEnrollmentToken(_ context.Context, hash string) (TenantID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	row, ok := m.tokens[hash]
	if !ok || !row.token.Usable(time.Now()) {
		// Unknown, expired and already consumed are one answer, exactly as they are for the redemption
		// itself. Distinguishing them here would be free reconnaissance in the one place a caller can
		// reach without any credential at all — and this resolver runs before the token is redeemed,
		// which is precisely when somebody guessing would be asking.
		return "", ErrTokenUnusable
	}
	return row.tenant, nil
}

// Subscribe registers interest in work for a host and returns a channel closed when some arrives.
func (m *Memory) Subscribe(hostID string) (<-chan struct{}, func()) {
	wake := make(chan struct{})

	m.mu.Lock()
	m.waiters[hostID] = append(m.waiters[hostID], wake)
	m.mu.Unlock()

	return wake, func() { m.removeWaiter(hostID, wake) }
}

// removeWaiter drops a waiter, whether it was woken or gave up.
//
// It is idempotent, because the caller always releases its subscription and the waker has usually
// already removed it.
func (m *Memory) removeWaiter(hostID string, wake chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	waiters := m.waiters[hostID]
	for i, w := range waiters {
		if w == wake {
			m.waiters[hostID] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(m.waiters[hostID]) == 0 {
		delete(m.waiters, hostID)
	}
}

// takeWaiters removes and returns the channels waiting for work for a host.
//
// The caller holds the lock and closes them after releasing it, which is what keeps a woken long-poll
// from blocking on the store's mutex the instant it comes back to read the queue.
func (m *Memory) takeWaiters(hostID string) []chan struct{} {
	waiters := m.waiters[hostID]
	delete(m.waiters, hostID)
	return waiters
}

// Enqueue adds a job needing no approval to one host's queue, and wakes any long-poll waiting for it.
//
// It is not part of the Store interface: it exists so that a test can put work in front of an agent in
// one line without assembling a NewJob. It goes through CreateJob rather than touching the maps itself,
// so that a test is exercising the same path the API uses — a helper that took a shortcut would be a
// test fixture that proved something the production path does not do.
//
// The tenant is a parameter rather than inferred from the host, deliberately. A helper that worked out
// which tenant a host id belonged to would be a way of reaching a host without naming its tenant, which
// is exactly what no caller is allowed to do.
func (m *Memory) Enqueue(tenant TenantID, hostID string, job protocol.Job) {
	//nolint:errcheck // CreateJob on the memory store fails only for a host that does not exist in this
	// tenant, and this helper is used by tests that have just created one. A test that got that wrong
	// fails on the assertion that follows rather than here, with a better message than this could
	// produce.
	_ = m.In(tenant).CreateJob(context.Background(), NewJob{Job: job, HostID: hostID})
}

// CertificateFingerprints returns one host's certificates that carry a supersession, for tests.
//
// Only the superseded ones, because the caller is a test moving a supersession into the past rather
// than enumerating a host's credentials — a helper that returned every fingerprint would invite a test
// to retire a certificate no renewal had replaced, which is a state the server never produces.
func (m *Memory) CertificateFingerprints(tenant TenantID, hostID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var found []string
	for fingerprint, cert := range m.certs {
		if cert.TenantID == tenant && cert.HostID == hostID && !cert.SupersededAt.IsZero() {
			found = append(found, fingerprint)
		}
	}
	sort.Strings(found)
	return found
}

// Result returns a recorded result, for tests.
//
// It takes the tenant for the same reason the job maps are keyed on one: a job id identifies a job only
// within a tenant, so a helper that looked one up without a tenant would be asserting about whichever
// of two jobs it happened to find.
func (m *Memory) Result(tenant TenantID, jobID string) (protocol.ResultRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.results[jobKey{tenant: tenant, id: jobID}]
	return r, ok
}

// scopedMemory is the in-memory Scoped: one tenant's view of one Memory.
//
// It holds a tenant rather than a private copy of the data, so the isolation it provides is the
// filtering in the methods below and nothing else. That is the point — see Memory. Every read filters
// on the tenant and every write records it, and a method handed an identifier belonging to somebody
// else answers the way the database will: ErrNotFound, or no rows.
type scopedMemory struct {
	// store is the shared store every tenant's handle reaches into.
	store *Memory

	// tenant is whose data this handle may see.
	tenant TenantID
}

// Tenant reports whose data this handle reaches.
func (s *scopedMemory) Tenant() TenantID { return s.tenant }

// host returns a host if it exists in this tenant. The caller holds the lock.
//
// Every host read goes through it so that "belongs to another tenant" and "does not exist" are one
// answer written once. Two spellings of that check would eventually disagree, and the one that
// disagreed by returning the row would not look like a bug from the caller's side.
func (s *scopedMemory) host(id string) (Host, bool) {
	row, ok := s.store.hosts[id]
	if !ok || row.tenant != s.tenant {
		return Host{}, false
	}
	return row.host, true
}

// stampCertificate fixes a certificate's tenant, or refuses one that names somebody else's.
//
// This is the WITH CHECK half of the row-level security policy. A caller that leaves the field empty
// gets the handle's tenant, which is the only one it could have meant; a caller that fills in a
// different one is refused rather than quietly corrected, because a certificate claiming another
// tenant is either a bug in the caller or the shape of a cross-tenant write, and both want to be loud.
func (s *scopedMemory) stampCertificate(c Certificate) (Certificate, error) {
	if c.TenantID == "" {
		c.TenantID = s.tenant
	}
	if c.TenantID != s.tenant {
		return Certificate{}, fmt.Errorf(
			"store: a certificate for tenant %q cannot be written by tenant %q", c.TenantID, s.tenant)
	}
	return c, nil
}

// CreateEnrollmentToken records a new token by its hash.
//
// The tenant must exist, matching the foreign key the token table has to tenants. The hash is unique
// across the installation and not merely within the tenant: it is the primary key of a table whose keys
// are SHA-256 digests of 256 bits of randomness, and it has to be, because resolving one to a tenant is
// how enrolment begins.
func (s *scopedMemory) CreateEnrollmentToken(_ context.Context, t EnrollmentToken) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tenants[s.tenant]; !ok {
		return errUnknownTenant(s.tenant)
	}
	if _, exists := m.tokens[t.Hash]; exists {
		return ErrConflict
	}
	m.tokens[t.Hash] = tokenRow{token: t, tenant: s.tenant}
	return nil
}

// ConsumeEnrollmentToken atomically redeems a token, or reports ErrTokenUnusable.
//
// The single mutex gives the same atomicity PostgreSQL gets from a conditional UPDATE: two agents
// presenting the same token concurrently cannot both succeed.
//
// A token belonging to another tenant is unusable here, not merely unmatched. Under row-level security
// the UPDATE simply sees no row, which is the same answer arrived at from the other direction.
func (s *scopedMemory) ConsumeEnrollmentToken(_ context.Context, hash, hostID string, now time.Time) (EnrollmentToken, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	row, ok := m.tokens[hash]
	if !ok || row.tenant != s.tenant || !row.token.Usable(now) {
		// One error for unknown, wrong tenant, expired and consumed. Distinguishing them for the caller
		// would mean distinguishing them for whoever is guessing tokens.
		return EnrollmentToken{}, ErrTokenUnusable
	}
	row.token.ConsumedAt = now
	row.token.ConsumedByHost = hostID
	m.tokens[hash] = row
	return row.token, nil
}

// ListEnrollmentTokens returns this tenant's tokens for the UI, newest first.
//
// The hash breaks ties. Tokens issued in the same instant are what a seeding script produces, and the
// database's own order is arbitrary in that case, so a deterministic one is worth more than a matching
// one.
func (s *scopedMemory) ListEnrollmentTokens(_ context.Context) ([]EnrollmentToken, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]EnrollmentToken, 0, len(m.tokens))
	for _, row := range m.tokens {
		if row.tenant != s.tenant {
			continue
		}
		out = append(out, row.token)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Hash < out[j].Hash
	})
	return out, nil
}

// CreateEnrolledHost records a newly enrolled host and its first certificate together.
//
// Both or neither, matching the transaction the PostgreSQL store runs. A host row without its
// certificate claims the machine-id hash while being unable to authenticate, which is a machine that
// cannot enrol again either.
//
// Each refusal is the schema's, in the schema's terms: the host id and the fingerprint are taken across
// the installation, because those are still primary keys; the machine-id hash is taken only within this
// tenant, because 0004 narrowed that index to (tenant_id, machine_id_hash) so that enrolling a machine
// somebody else already has does not tell you that they have it; and the certificate must name the host
// being enrolled, because the composite foreign key refuses one that points anywhere else.
//
// The host limit is checked here too, under the same lock the writes happen under, because that is what
// the PostgreSQL store does with its row lock and a test that passed against one implementation and not
// the other would be worse than no test.
func (s *scopedMemory) CreateEnrolledHost(_ context.Context, h Host, c Certificate) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	tenant, ok := m.tenants[s.tenant]
	if !ok {
		return errUnknownTenant(s.tenant)
	}
	if tenant.HostLimit != nil {
		// Active, not total: revoking a host is how an operator makes room for another one.
		active := 0
		for _, row := range m.hosts {
			if row.tenant == s.tenant && !row.host.Revoked {
				active++
			}
		}
		if active >= *tenant.HostLimit {
			return ErrHostLimitReached
		}
	}
	if c.HostID != h.ID {
		return fmt.Errorf("store: certificate %q names host %q, not the host being enrolled %q",
			c.Fingerprint, c.HostID, h.ID)
	}
	cert, err := s.stampCertificate(c)
	if err != nil {
		return err
	}
	if _, exists := m.hosts[h.ID]; exists {
		return ErrConflict
	}
	if _, exists := m.certs[cert.Fingerprint]; exists {
		return ErrConflict
	}
	if h.MachineIDHash != "" {
		for _, row := range m.hosts {
			if row.tenant == s.tenant && !row.host.Revoked && row.host.MachineIDHash == h.MachineIDHash {
				return ErrConflict
			}
		}
	}
	m.hosts[h.ID] = hostRow{host: h, tenant: s.tenant}
	m.certs[cert.Fingerprint] = cert
	return nil
}

// DeleteHost removes a host and everything that references it.
func (s *scopedMemory) DeleteHost(_ context.Context, hostID string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.host(hostID); !ok {
		return ErrNotFound
	}
	delete(m.hosts, hostID)
	for fingerprint, c := range m.certs {
		if c.TenantID == s.tenant && c.HostID == hostID {
			delete(m.certs, fingerprint)
		}
	}
	delete(m.jobs, queueKey{tenant: s.tenant, host: hostID})

	// The jobs go with the host, which is what ON DELETE CASCADE does on the other side. Leaving the
	// records behind is not merely untidy: a deleted host's pending destructive job would stay listed
	// and stay approvable, and approving it puts the job back on the queue of a host row that no longer
	// exists — so deleting a host would not cancel the work waiting for it.
	for key, rec := range m.records {
		if key.tenant == s.tenant && rec.HostID == hostID {
			delete(m.records, key)
			delete(m.results, key)
		}
	}
	return nil
}

// GetHost returns one host by id, or ErrNotFound.
func (s *scopedMemory) GetHost(_ context.Context, id string) (Host, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := s.host(id)
	if !ok {
		return Host{}, ErrNotFound
	}
	return h, nil
}

// GetHostByMachineID returns the live host with a machine-id hash, or ErrNotFound.
//
// Revoked hosts are skipped, matching the partial unique index in the schema: revoking a host is what
// releases its machine for re-enrolment. The search is inside this tenant, matching what 0004 narrowed
// that index to — across the installation it would answer "somebody else has this machine", which is
// the oracle the narrowing exists to close.
func (s *scopedMemory) GetHostByMachineID(_ context.Context, hash string) (Host, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if hash == "" {
		return Host{}, ErrNotFound
	}
	for _, row := range m.hosts {
		if row.tenant == s.tenant && row.host.MachineIDHash == hash && !row.host.Revoked {
			return row.host, nil
		}
	}
	return Host{}, ErrNotFound
}

// CountHosts returns how many hosts this tenant has, without returning any of them.
//
// Written out rather than delegating to ListHosts, for the reason every method in this file is: this
// stands in for a statement the database runs, and a stand-in that reached its answer differently would
// let a test pass here and fail there. The tenant filter is the same one, applied the same way.
func (s *scopedMemory) CountHosts(_ context.Context) (HostCounts, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	var counts HostCounts
	for _, row := range m.hosts {
		if row.tenant != s.tenant {
			continue
		}
		counts.Total++
		if !row.host.Revoked {
			counts.Active++
		}
	}
	return counts, nil
}

// ListHosts returns this tenant's hosts, ordered by hostname then id.
//
// The secondary sort on id matters: hostnames are not unique, and an unstable order would make the
// fleet list reshuffle between page loads for no reason a reader could see.
func (s *scopedMemory) ListHosts(_ context.Context) ([]Host, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Host, 0, len(m.hosts))
	for _, row := range m.hosts {
		if row.tenant != s.tenant {
			continue
		}
		out = append(out, row.host)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// RecordHeartbeat applies a heartbeat's fields to a host.
func (s *scopedMemory) RecordHeartbeat(_ context.Context, hostID string, u HeartbeatUpdate) error {
	return s.update(hostID, func(h *Host) {
		h.AgentVersion = u.AgentVersion
		h.BootID = u.BootID
		h.UptimeSeconds = u.UptimeSeconds
		h.ClockOffsetSeconds = u.ClockOffsetSeconds
		h.Paused = u.Paused
		h.LastSeen = u.LastSeen
	})
}

// StoreFacts records a full facts document and its digest.
func (s *scopedMemory) StoreFacts(_ context.Context, hostID, digest string, document []byte) error {
	return s.update(hostID, func(h *Host) {
		h.Facts = document
		h.FactsDigest = digest
	})
}

// StorePolicy records a host's effective policy and its digest.
func (s *scopedMemory) StorePolicy(_ context.Context, hostID, digest string, document []byte) error {
	return s.update(hostID, func(h *Host) {
		h.Policy = document
		h.PolicyDigest = digest
	})
}

// StoreSigners records a host's trusted key identities and their digest.
func (s *scopedMemory) StoreSigners(_ context.Context, hostID, digest string, document []byte) error {
	return s.update(hostID, func(h *Host) {
		h.Signers = document
		h.SignersDigest = digest
	})
}

// update applies a mutation to one of this tenant's hosts, under the lock.
//
// Every write to a host goes through it, so the tenant check is written once and cannot be the one a
// new method forgets — which, for a write, would not be a leak but something worse: one tenant's
// heartbeat landing on another's host row.
func (s *scopedMemory) update(hostID string, apply func(*Host)) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := s.host(hostID)
	if !ok {
		return ErrNotFound
	}
	apply(&h)
	m.hosts[hostID] = hostRow{host: h, tenant: s.tenant}
	return nil
}

// AddCertificate records an issued certificate by fingerprint.
//
// A fingerprint that is already recorded changes nothing and is not an error, matching the shipped
// store's ON CONFLICT DO NOTHING: a renewal generates a new key and therefore a new fingerprint, so the
// repeat that reaches this is a retry rather than a second certificate.
//
// The host must exist in this tenant. That is the composite foreign key, and it is what stops a
// certificate from being attached to somebody else's host — which would be a credential that
// authenticates as a machine its holder does not own.
func (s *scopedMemory) AddCertificate(_ context.Context, c Certificate) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, err := s.stampCertificate(c)
	if err != nil {
		return err
	}
	if _, ok := s.host(cert.HostID); !ok {
		return fmt.Errorf("store: certificate %q names host %q, which tenant %q does not have",
			cert.Fingerprint, cert.HostID, s.tenant)
	}
	if _, exists := m.certs[cert.Fingerprint]; exists {
		return nil
	}
	m.certs[cert.Fingerprint] = cert
	return nil
}

// SupersedeCertificate sets when a renewed-away certificate stops being accepted.
//
// The earlier time wins, matching the PostgreSQL LEAST: a host that renews twice in quick succession
// must not be able to push back the moment the credential it already replaced stops working.
func (s *scopedMemory) SupersedeCertificate(_ context.Context, fingerprint string, at time.Time) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, ok := m.certs[fingerprint]
	if !ok || cert.TenantID != s.tenant {
		return nil
	}
	if cert.SupersededAt.IsZero() || at.Before(cert.SupersededAt) {
		cert.SupersededAt = at
		m.certs[fingerprint] = cert
	}
	return nil
}

// RenewCertificate admits a replacement certificate and retires the one that asked for it.
//
// One lock held across the count and both writes, which is this store's whole answer to the question
// the PostgreSQL implementation answers with a row lock: nothing else runs in between. A store that
// released the lock between the count and the insert would let a test pass here and the shipped store
// exceed its own cap under the burst the renewal limiter permits.
func (s *scopedMemory) RenewCertificate(_ context.Context, r Renewal) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := s.host(r.Replacement.HostID); !ok {
		return ErrNotFound
	}

	live := 0
	for _, cert := range m.certs {
		switch {
		case cert.TenantID != s.tenant || cert.HostID != r.Replacement.HostID:
		case cert.Revoked:
		case !cert.NotAfter.After(r.Now):
		case !cert.SupersededAt.IsZero() && !cert.SupersededAt.After(r.Now):
		default:
			live++
		}
	}
	if live >= r.MaxLive {
		return ErrTooManyCertificates
	}

	replacement, err := s.stampCertificate(r.Replacement)
	if err != nil {
		return err
	}
	if _, exists := m.certs[replacement.Fingerprint]; !exists {
		m.certs[replacement.Fingerprint] = replacement
	}

	// The earlier time wins, so a host renewing twice in quick succession cannot push back the moment
	// the credential it already replaced stops working.
	if presented, ok := m.certs[r.Presented]; ok && presented.TenantID == s.tenant {
		if presented.SupersededAt.IsZero() || r.SupersedeAt.Before(presented.SupersededAt) {
			presented.SupersededAt = r.SupersedeAt
			m.certs[r.Presented] = presented
		}
	}
	return nil
}

// CountLiveCertificates returns how many of a host's certificates could still authenticate.
//
// The three conditions are written out rather than shared with a helper, and they are the same three
// the PostgreSQL query applies and the same three requireAgent applies. A count that disagreed with the
// middleware would give a cap that refused a host holding one working certificate, or admitted one
// holding twenty.
func (s *scopedMemory) CountLiveCertificates(_ context.Context, hostID string, now time.Time) (int, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	live := 0
	for _, cert := range m.certs {
		switch {
		case cert.TenantID != s.tenant || cert.HostID != hostID:
		case cert.Revoked:
		case !cert.NotAfter.After(now):
		case !cert.SupersededAt.IsZero() && !cert.SupersededAt.After(now):
		default:
			live++
		}
	}
	return live, nil
}

// RevokeHost marks a host and all its certificates as revoked.
func (s *scopedMemory) RevokeHost(_ context.Context, hostID string) error {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	h, ok := s.host(hostID)
	if !ok {
		return ErrNotFound
	}
	h.Revoked = true
	m.hosts[hostID] = hostRow{host: h, tenant: s.tenant}

	now := time.Now()
	for fingerprint, c := range m.certs {
		if c.TenantID == s.tenant && c.HostID == hostID {
			c.Revoked = true
			c.RevokedAt = now
			m.certs[fingerprint] = c
		}
	}
	return nil
}

// CreateJob records a job for one of this tenant's hosts and wakes any long-poll waiting for it.
func (s *scopedMemory) CreateJob(_ context.Context, j NewJob) error {
	m := s.store
	m.mu.Lock()

	if _, ok := s.host(j.HostID); !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	// The primary key, which PostgreSQL enforces for free and this has to state. Without it a second
	// job carrying an id that is already taken is silently accepted here and refused there — and worse,
	// the record would be overwritten while both copies stayed in the queue, so a host would receive one
	// job and the operator would read another under the same id.
	//
	// It is (tenant, id), as 0004 made it: the same id in another tenant is another job, and creating
	// it must succeed.
	key := jobKey{tenant: s.tenant, id: j.Job.ID}
	if _, taken := m.records[key]; taken {
		m.mu.Unlock()
		return ErrConflict
	}
	// The same refusal the partial unique index makes in PostgreSQL. A signed payload may be queued
	// once; an unsigned read job's nonce means nothing and is not checked, which is why the condition
	// is on the signature rather than on the nonce being non-empty.
	if j.Job.Signature != "" {
		for other, prev := range m.records {
			if other.tenant == s.tenant && prev.HostID == j.HostID && prev.Job.Nonce == j.Job.Nonce &&
				prev.Job.Signature != "" {
				m.mu.Unlock()
				return ErrConflict
			}
		}
	}

	m.records[key] = JobRecord{
		Job:                      j.Job,
		HostID:                   j.HostID,
		CreatedAt:                j.Job.IssuedAt,
		CreatedBy:                j.CreatedBy,
		ApprovalRequired:         j.ApprovalRequired,
		ApprovalDistinctOperator: j.ApprovalDistinctOperator,
	}

	// A job waiting for a second operator is not in the queue at all. Holding it back here rather than
	// filtering on claim keeps the two implementations honest about the same thing: the PostgreSQL
	// claim excludes it with a WHERE clause, and this one never offers it.
	var waiters []chan struct{}
	if !j.ApprovalRequired {
		queue := queueKey{tenant: s.tenant, host: j.HostID}
		m.jobs[queue] = append(m.jobs[queue], j.Job)
		waiters = m.takeWaiters(j.HostID)
	}
	m.mu.Unlock()

	for _, w := range waiters {
		close(w)
	}
	return nil
}

// ApproveJob records an operator's release of a job, making it claimable.
//
// The whole check happens under the lock, which is what PostgreSQL gets from putting the rules in the
// WHERE clause: two requests arriving at once must not let one operator satisfy a rule that says
// somebody else has to agree, by racing a job against itself.
//
// Whether the approver may be the creator comes from the job row rather than from the tenant's setting
// as it stands now. The row records what was decided when the job was created, so relaxing the tenant's
// mode cannot release work that was queued under a stricter one.
func (s *scopedMemory) ApproveJob(_ context.Context, jobID, approver string, now time.Time) error {
	m := s.store
	m.mu.Lock()

	key := jobKey{tenant: s.tenant, id: jobID}
	rec, ok := m.records[key]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if !rec.ApprovalRequired || !rec.ApprovedAt.IsZero() ||
		(rec.ApprovalDistinctOperator && rec.CreatedBy == approver) {
		m.mu.Unlock()
		return ErrConflict
	}

	rec.ApprovedAt = now
	rec.ApprovedBy = approver
	m.records[key] = rec

	queue := queueKey{tenant: s.tenant, host: rec.HostID}
	m.jobs[queue] = append(m.jobs[queue], rec.Job)
	waiters := m.takeWaiters(rec.HostID)
	m.mu.Unlock()

	for _, w := range waiters {
		close(w)
	}
	return nil
}

// ListJobs returns this tenant's jobs newest first, with their results.
//
// By creation time and then by id descending, which is the order the shipped query states and for the
// reason it states: a signed job's id comes from whoever signed it and can be any string, so ordering
// by identifier would file a queued reboot wherever its id happened to fall — possibly off the end of
// the page the second operator reads before approving it. The limit is applied after the ordering, as
// LIMIT is applied after ORDER BY, so a full page is the newest page and not an arbitrary one.
func (s *scopedMemory) ListJobs(_ context.Context, f JobFilter) ([]JobRecord, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	limit := clampJobLimit(f.Limit)
	out := make([]JobRecord, 0, limit)
	for key, rec := range m.records {
		if key.tenant != s.tenant {
			continue
		}
		if f.HostID != "" && rec.HostID != f.HostID {
			continue
		}
		if f.AwaitingApproval && !rec.AwaitingApproval() {
			continue
		}
		out = append(out, s.withResult(key, rec))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Job.ID > out[j].Job.ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// GetJob returns one job and its result, or ErrNotFound.
func (s *scopedMemory) GetJob(_ context.Context, jobID string) (JobRecord, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	key := jobKey{tenant: s.tenant, id: jobID}
	rec, ok := m.records[key]
	if !ok {
		return JobRecord{}, ErrNotFound
	}
	return s.withResult(key, rec), nil
}

// withResult attaches a job's result if one has been recorded. The caller holds the lock.
//
// It takes the key rather than deriving one from the record, so that a result can only ever be found
// under the tenant the record was found under.
func (s *scopedMemory) withResult(key jobKey, rec JobRecord) JobRecord {
	if result, ok := s.store.results[key]; ok {
		copied := result
		rec.Result = &copied
	}
	return rec
}

// ClaimJobs takes up to limit jobs for one of this tenant's hosts.
//
// Removing the jobs under the lock gives the same at-most-once delivery PostgreSQL gets from
// SELECT … FOR UPDATE SKIP LOCKED.
//
// A limit of zero or less takes the same ten the shipped store substitutes, rather than meaning
// "everything". A caller that does not choose a page size must get the same page from both, or a test
// that never sets one proves a delivery batch the shipped store would have split.
func (s *scopedMemory) ClaimJobs(_ context.Context, hostID string, limit int) ([]protocol.Job, error) {
	if limit <= 0 {
		limit = 10
	}

	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	queue := queueKey{tenant: s.tenant, host: hostID}
	pending := m.jobs[queue]
	if len(pending) == 0 {
		return nil, nil
	}

	// A job whose window has not opened stays in the queue. Handing one over early does not delay it,
	// it destroys it: the agent finds the window shut and reports that as a terminal status. Skipped
	// rather than stopping at the first one, because the queue is in creation order and a job scheduled
	// for next Sunday must not hold up the one queued after it for now.
	//
	// The server's clock decides delivery; the agent's own clock decides authorisation. Keeping those
	// separate is why this is not a shortcut for the window check in internal/agent.
	now := time.Now()
	var claimed, deferred []protocol.Job
	for _, job := range pending {
		if len(claimed) < limit && !job.NotBefore.After(now) {
			claimed = append(claimed, job)
			continue
		}
		deferred = append(deferred, job)
	}
	if len(claimed) == 0 {
		return nil, nil
	}
	if len(deferred) == 0 {
		delete(m.jobs, queue)
	} else {
		m.jobs[queue] = deferred
	}

	// The record is stamped as well as the queue emptied, so that an operator watching a job sees it
	// move from waiting to running. Without this the job would simply disappear from the queue and
	// stay "not started" on the screen until its result arrived, which on a forty-minute upgrade is a
	// long time to look like nothing is happening.
	for _, job := range claimed {
		key := jobKey{tenant: s.tenant, id: job.ID}
		if rec, ok := m.records[key]; ok {
			rec.ClaimedAt = now
			m.records[key] = rec
		}
	}
	return claimed, nil
}

// RecordResult stores a job result idempotently, for a job that belongs to the reporting host, and
// reports whether it was the first.
func (s *scopedMemory) RecordResult(_ context.Context, hostID string, r protocol.ResultRequest) (bool, error) {
	m := s.store
	m.mu.Lock()
	defer m.mu.Unlock()

	key := jobKey{tenant: s.tenant, id: r.JobID}
	rec, ok := m.records[key]

	// Every enrolled host is authenticated and none is trusted. A result for somebody else's job is
	// refused rather than stored, because recording is idempotent and a forged result would otherwise
	// suppress the real one when it arrived. A job id that names another tenant's job is not this
	// tenant's job at all, and answers the same way.
	//
	// And a result for work this host was never given is not a result. Without that a compromised host
	// could complete a destructive job that was still waiting for its second operator — the job is then
	// permanently excluded from the claim, cannot be re-queued because its signed nonce is taken, and
	// the dashboard shows "succeeded" for work nobody ever authorised, let alone performed.
	if !ok || rec.HostID != hostID || rec.ClaimedAt.IsZero() {
		return false, ErrNotFound
	}
	if _, exists := m.results[key]; exists {
		// Already recorded. A repeated result changes nothing and is not an error: the agent retries
		// until it gets a 2xx, and a second delivery means the first response was lost, not that the
		// work happened twice. False is what tells the caller not to notify twice about it.
		return false, nil
	}
	m.results[key] = r
	rec.CompletedAt = time.Now()
	m.records[key] = rec
	return true, nil
}
