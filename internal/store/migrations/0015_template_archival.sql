-- Withdrawing a template name from use, without deleting anything.
--
-- Until now the templates page offered no way to retire a template, and that was not an oversight: a
-- template version is immutable because a host's Tier 2 bootstrap record names one — "web-07 was
-- bootstrapped with standard-server v3" — and a record that resolves to nothing is no better than one
-- that resolves to editable bytes. docs/SECURITY.md §7 rests on that, so DELETE was never the answer.
--
-- What an operator actually wants when they reach for a delete button is "stop anybody using this",
-- and that is a different statement from "make the evidence go away". This table is the first one and
-- deliberately not the second:
--
--   * It is a row *about a name*, not a column on a version. Every row in `templates` stays written
--     once and never updated, which is the invariant the whole tier rests on — an UPDATE path added
--     here to carry a flag would be an UPDATE path, whatever it was first used for. Archiving a
--     template touches no version of it.
--
--   * It records who withdrew the name and when, because that is the question asked afterwards, when
--     an enrolment is refused and somebody has to say why.
--
-- Restoring is deleting this row, which is why the row carries nothing that would be lost. The
-- templates themselves are never reachable by any DELETE the server issues.
--
-- There is no foreign key to `templates`. The parent would have to be (tenant_id, name), which is not
-- unique there — a name is many versions by construction. The store checks existence in the same
-- transaction instead, and the ON DELETE CASCADE that matters, the tenant's, is present.

CREATE TABLE IF NOT EXISTS template_archivals (
    tenant_id   text        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name        text        NOT NULL,
    archived_at timestamptz NOT NULL DEFAULT now(),
    archived_by text        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, name)
);

-- Row-level security, exactly as migration 0005 built it for the templates themselves: enabled AND
-- forced, keyed on the transaction-local setting. Which templates a fleet has retired is a statement
-- about that fleet's provisioning, and it stays inside it.
ALTER TABLE template_archivals ENABLE ROW LEVEL SECURITY;
ALTER TABLE template_archivals FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS template_archivals_tenant_isolation ON template_archivals;
CREATE POLICY template_archivals_tenant_isolation ON template_archivals
    USING      (tenant_id = current_setting('hostseal.tenant', true))
    WITH CHECK (tenant_id = current_setting('hostseal.tenant', true));

COMMENT ON TABLE template_archivals IS
    'Template names withdrawn from use. An archived name is hidden from the default listing, refuses '
    'new versions, cannot be named by a new enrolment token, cannot be rendered, and is refused at '
    'enrolment. Every stored version stays readable, so a host''s bootstrap record still resolves to '
    'the bytes that ran. Deleting the row restores the name.';
