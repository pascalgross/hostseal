-- HostSeal initial schema.
--
-- The PostgreSQL features used here are load-bearing rather than incidental, which is why
-- docs/EXTENDING.md says store.Store is not a portability seam:
--
--   * JSONB with a GIN index for facts, because a fact document gains fields constantly and a column
--     per fact would mean a migration every time somebody adds one;
--   * a partial index for the job claim, so that claiming skips completed rows without scanning them;
--   * LISTEN/NOTIFY to wake long-polls, which is why HostSeal ships no Redis;
--   * SELECT ... FOR UPDATE SKIP LOCKED for atomic claiming, which is what lets the control plane run
--     more than one replica without delivering a job twice.

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    -- Only the SHA-256 of the token is stored. A database dump therefore does not let its holder enrol
    -- hosts, and the token itself is shown to the operator exactly once, at creation.
    hash             text PRIMARY KEY,
    label            text        NOT NULL DEFAULT '',
    fleet_group      text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    consumed_at      timestamptz,
    consumed_by_host text
);

CREATE TABLE IF NOT EXISTS hosts (
    id                   text PRIMARY KEY,
    -- Display only. Hostnames are not unique and a host can change its own, so identity is the
    -- certificate subject and never this.
    hostname             text        NOT NULL DEFAULT '',
    -- A salted hash. The raw /etc/machine-id is documented by systemd as confidential and is never
    -- transmitted or stored. Uniqueness is enforced by a partial index over live hosts only, so that
    -- revoking a host releases its machine for re-enrolment while its row stays for the audit trail.
    machine_id_hash      text,
    fleet_group          text        NOT NULL DEFAULT '',
    agent_version        text        NOT NULL DEFAULT '',
    enrolled_at          timestamptz NOT NULL,
    last_seen            timestamptz,
    boot_id              text        NOT NULL DEFAULT '',
    uptime_seconds       bigint      NOT NULL DEFAULT 0,
    -- The host's own measurement of its offset from the server. Stored for display and for flagging;
    -- nothing on the server adjusts anything because of it, and the host validates signature windows
    -- against its local clock only.
    clock_offset_seconds bigint      NOT NULL DEFAULT 0,
    paused               boolean     NOT NULL DEFAULT false,
    -- Digests are compared against the stored documents to decide whether to ask for a full report.
    -- That comparison is the entire digest-first design: without it, five hundred hosts send their
    -- whole inventory every minute.
    facts_digest         text        NOT NULL DEFAULT '',
    policy_digest        text        NOT NULL DEFAULT '',
    signers_digest       text        NOT NULL DEFAULT '',
    facts                jsonb,
    policy               jsonb,
    -- Key identities only, never the trusted-signers file itself. The control plane has no business
    -- holding a copy of a host's trust anchor.
    signers              jsonb,
    revoked              boolean     NOT NULL DEFAULT false
);

-- One live host per machine. Partial rather than a plain UNIQUE constraint: a decommissioned or
-- compromised machine is revoked, not deleted, and a plain constraint would mean its old row held the
-- machine id for ever — a host that could neither authenticate nor enrol again, recoverable only by
-- somebody editing the database by hand.
CREATE UNIQUE INDEX IF NOT EXISTS hosts_live_machine_id
    ON hosts (machine_id_hash)
    WHERE machine_id_hash IS NOT NULL AND NOT revoked;

CREATE INDEX IF NOT EXISTS hosts_facts_gin ON hosts USING gin (facts jsonb_path_ops);
CREATE INDEX IF NOT EXISTS hosts_group ON hosts (fleet_group);
CREATE INDEX IF NOT EXISTS hosts_last_seen ON hosts (last_seen DESC NULLS LAST);

CREATE TABLE IF NOT EXISTS certificates (
    -- SHA-256 of the DER certificate. Looked up on every authenticated request: this is the whole
    -- revocation mechanism, and it is why HostSeal ships neither a CRL nor an OCSP responder.
    fingerprint text PRIMARY KEY,
    host_id     text        NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    serial      text        NOT NULL,
    issued_at   timestamptz NOT NULL,
    not_after   timestamptz NOT NULL,
    revoked     boolean     NOT NULL DEFAULT false,
    revoked_at  timestamptz
);

CREATE INDEX IF NOT EXISTS certificates_host ON certificates (host_id);

CREATE TABLE IF NOT EXISTS jobs (
    id               text PRIMARY KEY,
    host_id          text        NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    -- A catalogue member name. There is no column here into which a command, a script, a path or a URL
    -- could be placed, and that is not an accident of schema design.
    intent           text        NOT NULL,
    params           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    class            text        NOT NULL,
    issued_at        timestamptz NOT NULL,
    not_before       timestamptz NOT NULL,
    not_after        timestamptz NOT NULL,
    nonce            text        NOT NULL,
    signature        text,
    signer_key_id    text,
    signer_algorithm text,
    claimed_at       timestamptz,
    completed_at     timestamptz
);

-- The partial index the claim runs against. Restricting it to unclaimed, uncompleted rows keeps it
-- small however much history accumulates, which is what stops job delivery slowing down over a year.
CREATE INDEX IF NOT EXISTS jobs_claimable
    ON jobs (host_id, issued_at)
    WHERE claimed_at IS NULL AND completed_at IS NULL;

CREATE TABLE IF NOT EXISTS job_results (
    -- Keyed by job id, which is what makes recording idempotent. Work that succeeded but whose result
    -- was lost must never re-execute: that is how a retry turns one reboot into a reboot loop.
    job_id           text PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    host_id          text        NOT NULL,
    status           text        NOT NULL,
    started_at       timestamptz,
    finished_at      timestamptz,
    exit_code        integer     NOT NULL DEFAULT 0,
    -- The last 64 KiB of output. The tail rather than the head, because the failure is at the end.
    output           text        NOT NULL DEFAULT '',
    output_truncated boolean     NOT NULL DEFAULT false,
    result           jsonb,
    error            text        NOT NULL DEFAULT '',
    recorded_at      timestamptz NOT NULL DEFAULT now()
);

-- Waking a long-poll. A trigger rather than an application-side NOTIFY so that a job inserted by any
-- path — the API, a maintenance script, a future scheduler — wakes the agent that is waiting for it.
CREATE OR REPLACE FUNCTION hostseal_notify_job() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('hostseal_job', NEW.host_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS jobs_notify ON jobs;
CREATE TRIGGER jobs_notify
    AFTER INSERT ON jobs
    FOR EACH ROW
EXECUTE FUNCTION hostseal_notify_job();
