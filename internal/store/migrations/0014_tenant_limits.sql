-- Two settings a hosting provider needs and a self-hoster never sets.
--
-- Multi-tenancy exists in this schema because one control plane may serve many independent fleets, and
-- whoever runs such an installation has a question the product has so far had no answer to: how many
-- hosts does a fleet have, and how do I stop one from growing past what it is entitled to. Both
-- answers have been reached, until now, by giving the hosting provider an operator account *inside* the
-- customer's fleet — because the platform role can create a tenant and read nothing in it, which is the
-- boundary working exactly as designed. An account inside the fleet is a credential that can queue
-- jobs, read facts and revoke hosts, held by somebody who wanted to count to three.
--
-- These two columns are the narrow answer, so that the wide one stops being necessary:
--
--   host_limit  how many hosts may be enrolled. NULL means no limit, which is what every
--               installation that is not selling this has.
--   suspended   whether the control plane answers this tenant's agents at all.
--
-- Four properties are what make them safe to add, and each is enforced somewhere rather than promised:
--
-- **The limit gates enrolment and nothing else.** It is checked in the enrolment handler, before the
-- token is consumed, alongside the machine-id check that is already there for the same reason: a
-- refusal must leave the token usable. Lowering a limit below a fleet's current size revokes nothing,
-- stops nothing and reaches no host — the hosts that are enrolled stay enrolled, and the next machine
-- to present a token is refused. That asymmetry is the point. A setting that could take a running host
-- away from its operator would be a lever on an enrolled host, and this project does not build those.
--
-- **Suspension is refusal, not reach.** A suspended tenant's agents are answered with 403 rather than
-- with work. The agent keeps running, keeps applying the host's own local policy and keeps installing
-- security updates on its own timer, exactly as it does when the control plane is simply unreachable —
-- which docs/INSTALL.md already documents as a supported state, because it is the one an outage
-- produces.
--
-- **Neither is a licence check.** They are rows an administrator of this installation sets, on an
-- installation they run. Nothing in the agent reads them, nothing phones home, and a fleet with
-- host_limit NULL — the default, and what `hostseal-server serve` creates — behaves exactly as it did
-- before this migration. Removing these columns from a fork removes a hosting feature and no
-- protection.
--
-- **The count they are read against respects row-level security.** Counting a fleet's hosts is done
-- through Store.In(tenant) like every other read of a tenant-owned table, so the platform API's usage
-- endpoint is a scoped statement and not an exemption. What that endpoint returns is a number and a
-- timestamp: not a hostname, not a fact, not a job. The platform role learns how large a fleet is and
-- still cannot learn what is in it, which is the smallest disclosure that makes billing per host
-- possible — and is the reason this migration exists rather than a documented recommendation to hand
-- the hosting provider an operator credential.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS host_limit integer,
    ADD COLUMN IF NOT EXISTS suspended  boolean NOT NULL DEFAULT false;

-- Zero is a meaningful limit — a fleet that may hold no hosts at all, which is what a tenant looks like
-- between being created and being paid for — so the constraint refuses negatives rather than requiring
-- a positive. NULL passes, because NULL is how a row says "no limit" and a CHECK that treated it as a
-- value would make the default unrepresentable.
ALTER TABLE tenants
    DROP CONSTRAINT IF EXISTS tenants_host_limit_nonnegative;
ALTER TABLE tenants
    ADD CONSTRAINT tenants_host_limit_nonnegative
    CHECK (host_limit IS NULL OR host_limit >= 0);

COMMENT ON COLUMN tenants.host_limit IS
    'How many hosts may be enrolled into this fleet; NULL for no limit, which is the default. Checked '
    'at enrolment, before the token is consumed. Lowering it below the current host count revokes '
    'nothing and reaches no machine: enrolled hosts stay enrolled and the next enrolment is refused.';

COMMENT ON COLUMN tenants.suspended IS
    'Whether the control plane refuses this fleet''s agent requests. A suspended fleet''s agents keep '
    'running on their own local policy and keep applying security updates on their own timer, exactly '
    'as they do when the control plane is unreachable. Nothing is uninstalled and no data is deleted.';
