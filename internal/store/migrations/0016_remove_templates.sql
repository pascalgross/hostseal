-- Provisioning templates are gone, and so are their tables.
--
-- The cloud-init template system — stored bodies, offline signatures over them, the archival of a
-- name, and the enrolment token's claim to one — was removed from the product. Nothing reads these
-- tables any more, so a database that still carried them would be carrying rows nothing can resolve:
-- an operator restoring a backup would see two tables the running server never mentions, and would
-- rightly wonder whether something was lost. Dropping them says plainly that nothing was.
--
-- IF EXISTS on every statement, because a database created after the templates migrations were
-- retired never had them: the sequence has to converge on the same schema whether it started before
-- or after this point.

DROP TABLE IF EXISTS template_archivals;
DROP TABLE IF EXISTS templates;

ALTER TABLE enrollment_tokens DROP COLUMN IF EXISTS bootstrap;
