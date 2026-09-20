package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pascalgross/hostseal/internal/protocol"
)

// databaseEnv names the environment variable holding a PostgreSQL URL for these tests.
//
// The tests skip when it is unset rather than failing, so that `go test ./...` works on a machine with
// no database. They are not optional in CI: the workflow sets it, because the PostgreSQL behaviour this
// store depends on — atomic claiming, LISTEN/NOTIFY, conditional updates — is not exercised by the
// in-memory store at all, and a test suite that only ran against Memory would prove nothing about the
// code that actually ships.
const databaseEnv = "HOSTSEAL_TEST_DATABASE_URL"

// newPostgres opens a migrated store and empties it, or skips the test.
//
// Every test starts from an empty schema rather than sharing state, because these tests assert things
// about counts and about uniqueness, and a leftover row from an earlier test is the kind of failure
// that only appears when the tests run in a different order.
func newPostgres(t *testing.T) *Postgres {
	t.Helper()

	dsn := os.Getenv(databaseEnv)
	if dsn == "" {
		t.Skipf("%s is not set; skipping the PostgreSQL store tests", databaseEnv)
	}

	ctx := context.Background()
	pg, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })

	if err := pg.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	truncate(t, pg)
	return pg
}

// testTenant creates a tenant and returns a handle scoped to it.
//
// Almost every test below is about one tenant's behaviour rather than about tenancy, so this exists to
// keep them saying what they are about. The tests that *are* about tenancy make two of these and check
// that neither can see the other.
func testTenant(t *testing.T, s Store, slug string, mode ApprovalMode) Scoped {
	t.Helper()

	tenant := Tenant{
		ID:           TenantID("tenant-" + slug),
		Slug:         slug,
		DisplayName:  slug,
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		ApprovalMode: mode,
	}
	if err := s.CreateTenant(context.Background(), tenant); err != nil {
		t.Fatalf("creating tenant %s: %v", slug, err)
	}
	return s.In(tenant.ID)
}

// eachScoped runs a test body against both implementations, inside one freshly created tenant.
//
// It is the ordinary harness: a test that is not about tenancy should not have to set one up, and one
// that forgot to would be testing an unreachable configuration, since every operator and every agent
// reaches the store through a tenant.
func eachScoped(t *testing.T, body func(t *testing.T, s Store, tenant Scoped)) {
	t.Helper()

	t.Run("memory", func(t *testing.T) {
		s := NewMemory()
		body(t, s, testTenant(t, s, "alpha", ApprovalSecondPerson))
	})
	t.Run("postgres", func(t *testing.T) {
		s := newPostgres(t)
		body(t, s, testTenant(t, s, "alpha", ApprovalSecondPerson))
	})
}

// enrolTestHost creates a host and returns it.
func enrolTestHost(t *testing.T, tenant Scoped, id, hostname string) Host {
	t.Helper()
	return enrolTestHostAs(t, tenant, id, hostname, "sha256:"+id)
}

// enrolTestHostAs enrols a host with a machine-id hash the caller chooses.
//
// It exists for the tenancy tests, which need the same physical machine live in two tenants at once —
// a thing the schema now permits, and the thing a store keyed on the machine-id hash alone would get
// wrong. Every other test wants a hash it never has to think about, which is what enrolTestHost gives.
func enrolTestHostAs(t *testing.T, tenant Scoped, id, hostname, machineID string) Host {
	t.Helper()

	host := Host{
		ID:            id,
		Hostname:      hostname,
		MachineIDHash: machineID,
		Group:         "web-prod",
		AgentVersion:  "0.0.0-test",
		EnrolledAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	// The fingerprint is namespaced by tenant as well as by host, because a fingerprint is globally
	// unique in the schema — it is the SHA-256 of a real certificate — and two tenants in the same test
	// enrolling "01JHOSTA" would otherwise collide on a constraint the isolation is not about.
	if err := tenant.CreateEnrolledHost(context.Background(), host, Certificate{
		Fingerprint: "fp-" + string(tenant.Tenant()) + "-" + id,
		HostID:      id,
		TenantID:    tenant.Tenant(),
		Serial:      "01",
		IssuedAt:    time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("creating host %s: %v", id, err)
	}
	return host
}

// TestMigrateIsIdempotent asserts a restart does not fail on an already-migrated database.
//
// Every replica calls Migrate on start, so this happens on every deploy. A migration that failed the
// second time would turn a rolling restart into an outage.
func TestMigrateIsIdempotent(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	for i := range 3 {
		if err := pg.Migrate(ctx); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
	}
}

// TestEnrollmentTokensAreConsumedAtomically is the property that stops one token enrolling two hosts.
//
// The condition is in the UPDATE rather than in a preceding SELECT precisely so that concurrent
// redemptions cannot both succeed. This runs them concurrently, because a check-then-update would pass
// a sequential test every time.
func TestEnrollmentTokensAreConsumedAtomically(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	now := time.Now()

	if err := tenant.CreateEnrollmentToken(ctx, EnrollmentToken{
		Hash: "hash-atomic", Label: "test", Group: "web-prod",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("creating a token: %v", err)
	}

	const racers = 8
	results := make(chan error, racers)
	start := make(chan struct{})
	for i := range racers {
		go func(i int) {
			<-start
			_, err := tenant.ConsumeEnrollmentToken(ctx, "hash-atomic", "host-"+string(rune('a'+i)), time.Now())
			results <- err
		}(i)
	}
	close(start)

	succeeded := 0
	for range racers {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTokenUnusable):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded; exactly one must", succeeded, racers)
	}
}

// TestExpiredAndUnknownTokensAreIndistinguishable asserts the store reveals nothing.
//
// Telling a caller whether a token was unknown, expired or already used is free reconnaissance for
// whoever is guessing, so the distinction is not carried out of the store at all.
func TestExpiredAndUnknownTokensAreIndistinguishable(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	now := time.Now()

	if err := tenant.CreateEnrollmentToken(ctx, EnrollmentToken{
		Hash: "hash-expired", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("creating an expired token: %v", err)
	}
	if err := tenant.CreateEnrollmentToken(ctx, EnrollmentToken{
		Hash: "hash-used", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("creating a token: %v", err)
	}
	if _, err := tenant.ConsumeEnrollmentToken(ctx, "hash-used", "host-1", now); err != nil {
		t.Fatalf("consuming: %v", err)
	}

	for _, hash := range []string{"hash-unknown", "hash-expired", "hash-used"} {
		_, err := tenant.ConsumeEnrollmentToken(ctx, hash, "host-2", now)
		if !errors.Is(err, ErrTokenUnusable) {
			t.Errorf("%s produced %v, want ErrTokenUnusable", hash, err)
		}
	}
}

// TestDuplicateMachineIDIsAConflict asserts a host cannot enrol twice under a new identity.
func TestDuplicateMachineIDIsAConflict(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()

	first := enrolTestHost(t, tenant, "01JHOSTA", "web-01")
	second := first
	second.ID = "01JHOSTB"

	if err := tenant.CreateEnrolledHost(ctx, second, Certificate{
		Fingerprint: "fp-second", HostID: second.ID, Serial: "01",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second host with the same machine id produced %v, want ErrConflict", err)
	}

	// The rejected enrolment left nothing behind. A certificate recorded for a host that was never
	// created would authenticate a request the fingerprint lookup then could not attribute.
	if _, err := pg.LookupCertificate(ctx, "fp-second"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refused enrolment recorded a certificate anyway: %v", err)
	}

	found, err := tenant.GetHostByMachineID(ctx, first.MachineIDHash)
	if err != nil {
		t.Fatalf("looking up by machine id: %v", err)
	}
	if found.ID != first.ID {
		t.Errorf("machine id lookup returned %s, want %s", found.ID, first.ID)
	}

	if _, err := tenant.GetHostByMachineID(ctx, "sha256:nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown machine id produced %v, want ErrNotFound", err)
	}
}

// TestHeartbeatDoesNotClobberFieldsItDoesNotCarry is the reason HeartbeatUpdate is its own type.
//
// A heartbeat writes only the columns it carries. Updating the whole row would let it overwrite the
// enrolment group or a stored facts document with a zero value, which is the sort of bug that shows up
// as data quietly disappearing.
func TestHeartbeatDoesNotClobberFieldsItDoesNotCarry(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	host := enrolTestHost(t, tenant, "01JHOSTC", "web-01")

	if err := tenant.StoreFacts(ctx, host.ID, "sha256:facts", []byte(`{"hostname":"web-01"}`)); err != nil {
		t.Fatalf("storing facts: %v", err)
	}

	if err := tenant.RecordHeartbeat(ctx, host.ID, HeartbeatUpdate{
		AgentVersion: "0.1.0", BootID: "boot-1", UptimeSeconds: 4242, LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("recording a heartbeat: %v", err)
	}

	after, err := tenant.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the host back: %v", err)
	}
	if after.Group != "web-prod" {
		t.Errorf("the heartbeat cleared the group: %q", after.Group)
	}
	if len(after.Facts) == 0 {
		t.Error("the heartbeat cleared the stored facts document")
	}
	if after.Hostname != "web-01" {
		t.Errorf("the heartbeat cleared the hostname: %q", after.Hostname)
	}
	if after.AgentVersion != "0.1.0" || after.UptimeSeconds != 4242 {
		t.Errorf("the heartbeat did not apply its own fields: %+v", after)
	}
	// The digest columns record what the server holds and are written only when a document arrives, so
	// the one stored above must survive a heartbeat untouched.
	if after.FactsDigest != "sha256:facts" {
		t.Errorf("the heartbeat changed the stored facts digest to %q", after.FactsDigest)
	}

	if err := tenant.RecordHeartbeat(ctx, "01JNOSUCHHOST", HeartbeatUpdate{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a heartbeat for an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestStoreDocumentRejectsInvalidJSON asserts a bad document cannot poison a JSONB column.
func TestStoreDocumentRejectsInvalidJSON(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	host := enrolTestHost(t, tenant, "01JHOSTD", "web-01")

	if err := tenant.StoreFacts(ctx, host.ID, "sha256:bad", []byte("not json at all")); err == nil {
		t.Error("an invalid facts document was accepted")
	}
	if err := tenant.StorePolicy(ctx, "01JNOSUCHHOST", "sha256:x", []byte(`{}`)); !errors.Is(err, ErrNotFound) {
		t.Errorf("storing a document for an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestRevokeHostRevokesItsCertificatesInTheSameTransaction is the revocation mechanism.
//
// A host marked revoked whose certificates were not would keep authenticating; certificates revoked
// without the host would leave a host that could re-enrol. Both must happen or neither.
func TestRevokeHostRevokesItsCertificatesInTheSameTransaction(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	host := enrolTestHost(t, tenant, "01JHOSTE", "web-01")

	for _, fingerprint := range []string{"fp-1", "fp-2"} {
		if err := tenant.AddCertificate(ctx, Certificate{
			Fingerprint: fingerprint, HostID: host.ID, Serial: "01",
			IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		}); err != nil {
			t.Fatalf("adding %s: %v", fingerprint, err)
		}
	}

	// Adding the same fingerprint twice must not fail: an agent that retried a renewal whose response
	// was lost would otherwise be unable to re-key.
	if err := tenant.AddCertificate(ctx, Certificate{
		Fingerprint: "fp-1", HostID: host.ID, Serial: "01",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("re-adding a certificate: %v", err)
	}

	if err := tenant.RevokeHost(ctx, host.ID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	for _, fingerprint := range []string{"fp-1", "fp-2"} {
		cert, err := pg.LookupCertificate(ctx, fingerprint)
		if err != nil {
			t.Fatalf("looking up %s: %v", fingerprint, err)
		}
		if !cert.Revoked {
			t.Errorf("%s was not revoked with its host", fingerprint)
		}
		if cert.RevokedAt.IsZero() {
			t.Errorf("%s was revoked with no timestamp", fingerprint)
		}
	}

	after, err := tenant.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("reading the host: %v", err)
	}
	if !after.Revoked {
		t.Error("the host was not marked revoked")
	}
	if err := tenant.RevokeHost(ctx, "01JNOSUCHHOST"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestClaimJobsDeliversEachJobExactlyOnce is what lets the control plane run more than one replica.
//
// SELECT ... FOR UPDATE SKIP LOCKED against the partial index means two instances claiming for the same
// host at the same moment take disjoint rows rather than blocking or double-delivering. Delivering a
// reboot twice is the failure this prevents.
func TestClaimJobsDeliversEachJobExactlyOnce(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	host := enrolTestHost(t, tenant, "01JHOSTF", "web-01")

	const jobs = 20
	for i := range jobs {
		enqueue(t, pg, tenant.Tenant(), host.ID, protocol.Job{
			ID: "01JJOB" + string(rune('A'+i)), Intent: "facts.collect", Class: "read",
			Params: map[string]any{}, IssuedAt: time.Now(),
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Nonce: "n",
		})
	}

	const claimers = 6
	type claim struct {
		jobs []protocol.Job
		err  error
	}
	results := make(chan claim, claimers)
	start := make(chan struct{})
	for range claimers {
		go func() {
			<-start
			claimed, err := tenant.ClaimJobs(ctx, host.ID, 5)
			results <- claim{claimed, err}
		}()
	}
	close(start)

	seen := map[string]int{}
	total := 0
	for range claimers {
		result := <-results
		if result.err != nil {
			t.Errorf("claiming: %v", result.err)
			continue
		}
		for _, j := range result.jobs {
			seen[j.ID]++
			total++
		}
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("job %s was delivered %d times", id, count)
		}
	}
	if total != jobs {
		t.Errorf("%d of %d jobs were delivered", total, jobs)
	}

	// A second round must find nothing: claimed jobs are excluded by the partial index.
	remaining, err := tenant.ClaimJobs(ctx, host.ID, 100)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d jobs were still claimable after every one had been claimed", len(remaining))
	}
}

// TestRecordResultIsIdempotent asserts a redelivered result changes nothing.
//
// The agent retries until it gets a 2xx, so a lost response means a second delivery. Work that
// succeeded but whose result was lost must never re-execute, and overwriting a genuine record with a
// retry's view of it would be the same class of mistake.
func TestRecordResultIsIdempotent(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()
	host := enrolTestHost(t, tenant, "01JHOSTG", "web-01")

	enqueue(t, pg, tenant.Tenant(), host.ID, protocol.Job{
		ID: "01JJOBRESULT", Intent: "facts.collect", Class: "read", Params: map[string]any{},
		IssuedAt: time.Now(), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Nonce: "n",
	})
	if _, err := tenant.ClaimJobs(ctx, host.ID, 1); err != nil {
		t.Fatalf("claiming: %v", err)
	}

	result := protocol.ResultRequest{
		JobID: "01JJOBRESULT", Status: protocol.StatusSucceeded,
		StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now(),
		Result: map[string]any{"hostname": "web-01"},
	}
	for i := range 3 {
		if _, err := tenant.RecordResult(ctx, host.ID, result); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}

	// A completed job must not become claimable again, however many times its result arrives.
	claimable, err := tenant.ClaimJobs(ctx, host.ID, 10)
	if err != nil {
		t.Fatalf("claiming after completion: %v", err)
	}
	if len(claimable) != 0 {
		t.Errorf("a completed job was claimable again")
	}
}

// TestSubscribeWakesOnNotify is what makes the long-poll a long-poll rather than a sleep.
//
// Without it, jobs would still be delivered — on the next poll, up to twenty-five seconds later — and
// nothing would look broken. It is the failure people notice as "why is this so slow" months
// afterwards.
func TestSubscribeWakesOnNotify(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)

	host := enrolTestHost(t, tenant, "01JHOSTH", "web-01")

	notified, unsubscribe := pg.Subscribe(host.ID)
	defer unsubscribe()

	// Wait for the listener rather than sleeping for it. A fixed sleep is a test that passes on a fast
	// machine and fails on a loaded one, and this is the assertion that would be quietly disabled first.
	select {
	case <-pg.ready:
	case <-time.After(15 * time.Second):
		t.Fatal("the notification listener never issued its LISTEN")
	}

	started := time.Now()
	enqueue(t, pg, tenant.Tenant(), host.ID, protocol.Job{
		ID: "01JJOBWAKE", Intent: "facts.collect", Class: "read", Params: map[string]any{},
		IssuedAt: time.Now(), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Nonce: "n",
	})

	select {
	case <-notified:
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Errorf("the wake-up took %s; LISTEN/NOTIFY is not delivering", elapsed.Round(time.Millisecond))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Subscribe was never woken by an enqueued job")
	}
}

// TestSubscribeReleasesItsWaiter asserts a released subscription leaves nothing behind.
//
// A fleet whose agents time out and reconnect every twenty-five seconds would otherwise accumulate a
// dead channel per poll for the process's lifetime — a leak that only shows after a week of uptime,
// which is the worst kind.
func TestSubscribeReleasesItsWaiter(t *testing.T) {
	pg := newPostgres(t)

	_, unsubscribe := pg.Subscribe("01JNOBODY")
	if waiterCount(pg) != 1 {
		t.Fatalf("%d waiters after subscribing once", waiterCount(pg))
	}
	unsubscribe()
	if n := waiterCount(pg); n != 0 {
		t.Errorf("%d waiter(s) were left behind after releasing the subscription", n)
	}
	// Releasing twice must not panic or corrupt the map: the caller always releases, and the waker has
	// usually already removed the waiter.
	unsubscribe()
	if n := waiterCount(pg); n != 0 {
		t.Errorf("%d waiter(s) after a second release", n)
	}
}

// TestListHostsIsOrdered asserts the fleet list does not reshuffle between page loads.
//
// Hostnames are not unique, so the secondary sort on id is what makes the order stable. Without it a
// reader watching a fleet list would see rows move for no reason they could see.
func TestListHostsIsOrdered(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()

	enrolTestHost(t, tenant, "01JHOSTZ", "web-02")
	enrolTestHost(t, tenant, "01JHOSTY", "web-01")
	enrolTestHost(t, tenant, "01JHOSTX", "web-01")

	hosts, err := tenant.ListHosts(ctx)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("listed %d hosts, want 3", len(hosts))
	}
	want := []string{"01JHOSTX", "01JHOSTY", "01JHOSTZ"}
	for i, id := range want {
		if hosts[i].ID != id {
			t.Errorf("position %d is %s (%s), want %s", i, hosts[i].ID, hosts[i].Hostname, id)
		}
	}
}

// truncate empties every table, so each test starts from a known schema.
//
// These tests assert things about counts and about uniqueness, and a row left over from an earlier test
// is the kind of failure that only appears when the tests happen to run in a different order.
func truncate(t *testing.T, pg *Postgres) {
	t.Helper()
	_, err := pg.pool.Exec(context.Background(),
		`TRUNCATE job_results, jobs, certificates, hosts, enrollment_tokens, tenants
		 RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("emptying the schema: %v", err)
	}
}

// enqueue inserts a job directly, bypassing CreateJob.
//
// It predates CreateJob and is kept deliberately: the tests below are about the *delivery* path, and
// writing the row with plain SQL means they still fail if CreateJob is what breaks, rather than both
// going quiet together. The tests that exercise CreateJob itself are in jobs_test.go and run against
// both implementations.
func enqueue(t *testing.T, pg *Postgres, tenant TenantID, hostID string, job protocol.Job) {
	t.Helper()
	params, err := json.Marshal(job.Params)
	if err != nil {
		t.Fatalf("encoding job parameters: %v", err)
	}

	ctx := context.Background()
	// In a transaction that names the tenant, because the jobs table is under a row-level security
	// policy and this statement is outside the code that normally sets it. Writing the tenant into the
	// INSERT alone is not enough: the policy's WITH CHECK is evaluated against hostseal.tenant, so an
	// insert that merely *claims* a tenant without the session saying so is refused. That refusal is
	// the boundary working — this helper deliberately bypasses CreateJob, and the database noticed.
	tx, err := pg.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("beginning: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('hostseal.tenant', $1, true)`, string(tenant)); err != nil {
		t.Fatalf("setting the tenant: %v", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO jobs (id, host_id, tenant_id, intent, params, class, issued_at, not_before,
		                  not_after, nonce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		job.ID, hostID, string(tenant), job.Intent, params, job.Class,
		job.IssuedAt, job.NotBefore, job.NotAfter, job.Nonce)
	if err != nil {
		t.Fatalf("enqueueing %s: %v", job.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("committing %s: %v", job.ID, err)
	}
}

// waiterCount reports how many long-polls are currently registered.
//
// It reaches into the store's internals because that is the only way to observe a leak: a waiter that
// is never released is invisible from outside until the process has been up for a week.
func waiterCount(pg *Postgres) int {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	total := 0
	for _, waiters := range pg.waiters {
		total += len(waiters)
	}
	return total
}

// TestRevokingAHostReleasesItsMachineForReEnrolment is the recovery path out of a 409.
//
// A machine-id hash held for ever by a row nobody can authenticate as is a wedge: the machine cannot
// talk, and enrolling it again is refused because it is "already enrolled". Revocation has to be the
// way out, and it has to leave the old row in place — an audit asking what that host reported before it
// was revoked is exactly the question revocation exists to make answerable.
func TestRevokingAHostReleasesItsMachineForReEnrolment(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()

	first := enrolTestHost(t, tenant, "01JHOSTM", "web-01")
	if err := tenant.RevokeHost(ctx, first.ID); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	// The machine no longer resolves to a live host, which is what the enrolment handler checks.
	if _, err := tenant.GetHostByMachineID(ctx, first.MachineIDHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revoked host still claims its machine id: %v", err)
	}

	second := first
	second.ID = "01JHOSTN"
	if err := tenant.CreateEnrolledHost(ctx, second, Certificate{
		Fingerprint: "fp-rejoin", HostID: second.ID, Serial: "02",
		IssuedAt: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("re-enrolling a revoked machine: %v", err)
	}

	found, err := tenant.GetHostByMachineID(ctx, first.MachineIDHash)
	if err != nil {
		t.Fatalf("looking up the re-enrolled host: %v", err)
	}
	if found.ID != second.ID {
		t.Errorf("the machine id resolves to %s, want the re-enrolled %s", found.ID, second.ID)
	}

	// The revoked row is still there, with its history.
	if _, err := tenant.GetHost(ctx, first.ID); err != nil {
		t.Errorf("re-enrolment erased the revoked host: %v", err)
	}
}

// TestDeleteHostTakesItsDependentRowsWithIt covers the operator's other way out of a wedge.
//
// Revocation keeps the history; deletion is for the row that should not exist at all. Either way the
// machine must be able to enrol again, and nothing may be left pointing at a host that is gone — a
// certificate outliving its host would be a fingerprint that authenticates and resolves to nobody.
func TestDeleteHostTakesItsDependentRowsWithIt(t *testing.T) {
	pg := newPostgres(t)
	tenant := testTenant(t, pg, "alpha", ApprovalSecondPerson)
	ctx := context.Background()

	host := enrolTestHost(t, tenant, "01JHOSTP", "web-01")
	if err := tenant.DeleteHost(ctx, host.ID); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if _, err := tenant.GetHost(ctx, host.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the deleted host is still readable: %v", err)
	}
	if _, err := pg.LookupCertificate(ctx, "fp-"+host.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a certificate outlived the host it was issued to: %v", err)
	}
	if _, err := tenant.GetHostByMachineID(ctx, host.MachineIDHash); !errors.Is(err, ErrNotFound) {
		t.Errorf("the deleted host still claims its machine id: %v", err)
	}
	if err := tenant.DeleteHost(ctx, "01JNOSUCHHOST"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting an unknown host produced %v, want ErrNotFound", err)
	}
}

// TestGuaranteeAHostLimitHoldsAgainstSimultaneousEnrolments enrols more machines at once than the
// fleet may hold, and asserts the fleet does not exceed its limit.
//
// This is the test for a race a code review found and the earlier tests did not: the server counted a
// fleet's hosts in one statement and wrote the new host in another, so two machines presenting two
// valid tokens into a fleet with one slot left both read a count with room in it and both wrote. The
// limit is the entitlement a customer is billed against, and batch provisioning — a autoscaling group
// coming up, a rack being enrolled from a loop — makes simultaneous enrolment the ordinary case rather
// than the unlucky one.
//
// It runs against PostgreSQL only, deliberately. The in-memory store takes one lock around the whole
// operation, so it cannot exhibit this bug and cannot prove its absence either; what is being tested is
// that the row lock and the transaction do their job against a real database with real concurrency.
func TestGuaranteeAHostLimitHoldsAgainstSimultaneousEnrolments(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()

	const limit = 3
	const racers = 12

	scoped := testTenant(t, pg, "crowded", ApprovalNone)
	allowed := limit
	if _, err := pg.UpdateTenant(ctx, scoped.Tenant(), TenantPatch{
		SetHostLimit: true, HostLimit: &allowed,
	}); err != nil {
		t.Fatalf("setting the host limit: %v", err)
	}

	// All of them wait on one channel and are released together, which is what makes this a race rather
	// than twelve sequential enrolments that happen to use goroutines.
	start := make(chan struct{})
	results := make(chan error, racers)
	for i := range racers {
		go func() {
			id := fmt.Sprintf("01JRACER%04d", i)
			host := Host{
				ID:            id,
				Hostname:      id + ".example",
				MachineIDHash: "sha256:" + id,
				Group:         "web-prod",
				AgentVersion:  "0.0.0-test",
				EnrolledAt:    time.Now().UTC().Truncate(time.Microsecond),
			}
			<-start
			results <- scoped.CreateEnrolledHost(ctx, host, Certificate{
				Fingerprint: "fp-race-" + id,
				HostID:      id,
				TenantID:    scoped.Tenant(),
				Serial:      "01",
				IssuedAt:    time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
			})
		}()
	}
	close(start)

	enrolled, refused := 0, 0
	for range racers {
		switch err := <-results; {
		case err == nil:
			enrolled++
		case errors.Is(err, ErrHostLimitReached):
			refused++
		default:
			t.Fatalf("enrolling: unexpected error %v", err)
		}
	}

	if enrolled != limit || refused != racers-limit {
		t.Fatalf("with a limit of %d and %d simultaneous enrolments: %d enrolled and %d refused; want %d and %d",
			limit, racers, enrolled, refused, limit, racers-limit)
	}

	// The database is the authority on what happened, not the return values: a store that answered nil
	// and wrote nothing would pass the count above.
	counts, err := scoped.CountHosts(ctx)
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	if counts.Active != limit {
		t.Fatalf("the fleet holds %d active hosts, over a limit of %d", counts.Active, limit)
	}
}

// TestAFleetWithNoLimitTakesEveryHostOfferedToIt asserts the lock added for the limit did not turn a
// nil limit into a small one.
//
// The check and the row lock run on every enrolment, limit or no limit. A bug there — reading NULL as
// zero, say — would refuse every enrolment on every unlimited fleet, which is every fleet on an
// ordinary installation.
func TestAFleetWithNoLimitTakesEveryHostOfferedToIt(t *testing.T) {
	pg := newPostgres(t)
	scoped := testTenant(t, pg, "unlimited", ApprovalNone)

	for i := range 5 {
		enrolTestHost(t, scoped, fmt.Sprintf("01JOPEN%05d", i), "open.example")
	}

	counts, err := scoped.CountHosts(context.Background())
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	if counts.Active != 5 {
		t.Fatalf("a fleet with no limit holds %d of 5 hosts offered", counts.Active)
	}
}

// TestConcurrentTenantEditsDoNotOverwriteEachOther changes two settings at once and asserts both stick.
//
// The test for a lost update that review found. `UpdateTenant` used to take a whole `Tenant`, so every
// caller read the row, changed one field and wrote back all of them — and whichever committed last
// silently restored the other's stale values. The hosting layer sets a fleet's host limit and its
// suspension through two separate requests, which made this the shape of a fleet coming back out of
// suspension because something else touched the row in between.
//
// Sequential rather than parallel on purpose: the interleaving that loses an update is read-read-write-
// write, and doing it by hand is deterministic where two goroutines would be a test that passes on a
// fast machine.
func TestConcurrentTenantEditsDoNotOverwriteEachOther(t *testing.T) {
	pg := newPostgres(t)
	ctx := context.Background()
	scoped := testTenant(t, pg, "contended", ApprovalNone)

	// Both editors read the same starting row, as two handlers serving two requests would.
	before, err := pg.GetTenant(ctx, scoped.Tenant())
	if err != nil {
		t.Fatalf("reading the tenant: %v", err)
	}
	if before.Suspended || before.HostLimit != nil {
		t.Fatalf("a new tenant should start unsuspended and unlimited, got %+v", before)
	}

	// One suspends the fleet. The other, holding the row it read *before* that, sets a host limit.
	suspended := true
	if _, err := pg.UpdateTenant(ctx, scoped.Tenant(), TenantPatch{Suspended: &suspended}); err != nil {
		t.Fatalf("suspending: %v", err)
	}
	limit := 3
	after, err := pg.UpdateTenant(ctx, scoped.Tenant(), TenantPatch{SetHostLimit: true, HostLimit: &limit})
	if err != nil {
		t.Fatalf("setting the limit: %v", err)
	}

	// The second edit must not have carried `suspended = false` back with it.
	if !after.Suspended {
		t.Error("setting a host limit put a suspended fleet back into service")
	}
	if after.HostLimit == nil || *after.HostLimit != limit {
		t.Errorf("host limit is %v, want %d", after.HostLimit, limit)
	}

	// And the row the database holds agrees with what the update returned.
	stored, err := pg.GetTenant(ctx, scoped.Tenant())
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if !stored.Suspended || stored.HostLimit == nil || *stored.HostLimit != limit {
		t.Errorf("stored tenant is %+v, want suspended with a limit of %d", stored, limit)
	}

	// Removing the limit is a different request from leaving it alone, which is the whole reason
	// SetHostLimit exists beside a nil-able HostLimit.
	cleared, err := pg.UpdateTenant(ctx, scoped.Tenant(), TenantPatch{SetHostLimit: true, HostLimit: nil})
	if err != nil {
		t.Fatalf("clearing the limit: %v", err)
	}
	if cleared.HostLimit != nil {
		t.Errorf("host limit is %v after an explicit clear, want nil", cleared.HostLimit)
	}
	if !cleared.Suspended {
		t.Error("clearing the limit also cleared the suspension")
	}

	// A patch that carries nothing changes nothing.
	untouched, err := pg.UpdateTenant(ctx, scoped.Tenant(), TenantPatch{})
	if err != nil {
		t.Fatalf("empty patch: %v", err)
	}
	if !untouched.Suspended || untouched.HostLimit != nil || untouched.DisplayName != before.DisplayName {
		t.Errorf("an empty patch changed something: %+v", untouched)
	}
}
