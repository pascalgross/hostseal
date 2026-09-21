package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// templateColumns is the projection every template read shares, in the order scanTemplate expects.
//
// One constant for the same reason jobColumns is one: two readers that select different shapes produce
// a version that is complete on the enrolment path and missing its signer in the listing, which reads
// as a bug in whichever client noticed first.
const templateColumns = `name, version, body_sealed, signature, signer_key_id, signer_algorithm,
	created_at, created_by`

// scanTemplate reads one template version from a row using the templateColumns projection.
func scanTemplate(row pgx.Row) (TemplateVersion, error) {
	var t TemplateVersion
	err := row.Scan(&t.Name, &t.Version, &t.BodySealed, &t.Signature, &t.SignerKeyID,
		&t.SignerAlgorithm, &t.CreatedAt, &t.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateVersion{}, ErrNotFound
	}
	if err != nil {
		return TemplateVersion{}, wrap(err, "reading a template")
	}
	return t, nil
}

// CreateTemplateVersion stores the next version of a template and returns the number it was given.
//
// The version is computed and inserted in one statement, so the assignment is atomic per transaction
// rather than per round trip. Two operators saving concurrently can still compute the same number —
// the SELECT sees the table before either INSERT commits — and then the primary key refuses the second
// one, which surfaces as ErrConflict for the caller to retry. A retry gets the next number; nothing is
// ever overwritten, which is the property the Tier 2 bootstrap record depends on.
func (s *scopedPostgres) CreateTemplateVersion(ctx context.Context, t TemplateVersion) (int, error) {
	var version int
	err := s.withTenant(ctx, "storing a template version", func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO templates (tenant_id, name, version, body_sealed, signature, signer_key_id,
			                       signer_algorithm, created_at, created_by)
			SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7, $8
			  FROM templates
			 WHERE tenant_id = $1 AND name = $2
			RETURNING version`,
			string(s.tenant), t.Name, t.BodySealed, t.Signature, t.SignerKeyID, t.SignerAlgorithm,
			t.CreatedAt, t.CreatedBy,
		).Scan(&version)
		return wrap(err, "storing a template version")
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// ListTemplates returns one summary per template name, newest latest-version first.
//
// DISTINCT ON with a matching ORDER BY is the idiomatic PostgreSQL "latest row per group", and it runs
// against the primary key: for each (tenant, name) the highest version wins, and the outer sort puts
// the most recently changed template first, which is the order an operator scanning the page wants.
//
// The archival is a LEFT JOIN rather than a second query, so a name cannot appear live in the listing
// because its withdrawal was read a moment later, and the filter is on the joined row rather than on a
// NOT EXISTS so that one statement serves both callers.
func (s *scopedPostgres) ListTemplates(ctx context.Context, includeArchived bool) ([]TemplateSummary, error) {
	var out []TemplateSummary
	err := s.withTenant(ctx, "listing templates", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT latest.name, latest.version, latest.created_at, latest.created_by,
			       (latest.signature <> '' AND latest.signer_key_id <> ''
			            AND latest.signer_algorithm <> '') AS signed,
			       a.archived_at, COALESCE(a.archived_by, '')
			  FROM (SELECT DISTINCT ON (name) name, version, created_at, created_by, signature,
			               signer_key_id, signer_algorithm
			          FROM templates
			         WHERE tenant_id = $1
			         ORDER BY name, version DESC) AS latest
			  LEFT JOIN template_archivals AS a
			         ON a.tenant_id = $1 AND a.name = latest.name
			 WHERE $2 OR a.name IS NULL
			 ORDER BY latest.created_at DESC`, string(s.tenant), includeArchived)
		if err != nil {
			return wrap(err, "listing templates")
		}
		defer rows.Close()

		for rows.Next() {
			var t TemplateSummary
			var archivedAt *time.Time
			if err := rows.Scan(&t.Name, &t.LatestVersion, &t.CreatedAt, &t.CreatedBy,
				&t.Signed, &archivedAt, &t.ArchivedBy); err != nil {
				return wrap(err, "scanning a template summary")
			}
			if archivedAt != nil {
				t.Archived, t.ArchivedAt = true, *archivedAt
			}
			out = append(out, t)
		}
		return wrap(rows.Err(), "listing templates")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ArchiveTemplate withdraws a template name from use, leaving every stored version intact.
//
// The INSERT is conditional on the name existing, in one statement, so that "no such template" and
// "already archived" are told apart without a read the caller could race: no rows inserted means the
// name has no versions, and the primary key refuses a second archival as ErrConflict. There is no
// UPDATE and no DELETE against `templates` anywhere in this file, which is the property the whole tier
// rests on.
func (s *scopedPostgres) ArchiveTemplate(ctx context.Context, a TemplateArchival) error {
	return s.withTenant(ctx, "archiving a template", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO template_archivals (tenant_id, name, archived_at, archived_by)
			SELECT $1, $2, $3, $4
			 WHERE EXISTS (SELECT 1 FROM templates WHERE tenant_id = $1 AND name = $2)`,
			string(s.tenant), a.Name, a.ArchivedAt, a.ArchivedBy)
		if err != nil {
			return wrap(err, "archiving a template")
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RestoreTemplate puts an archived template name back into use.
//
// The existence check and the delete run in one transaction, so the two refusals stay distinct: a name
// nobody ever stored is ErrNotFound, and a live name is ErrConflict — which is what a client acting on
// a stale listing needs to hear, rather than a success that changed nothing.
func (s *scopedPostgres) RestoreTemplate(ctx context.Context, name string) error {
	return s.withTenant(ctx, "restoring a template", func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM templates WHERE tenant_id = $1 AND name = $2)`,
			string(s.tenant), name).Scan(&exists); err != nil {
			return wrap(err, "restoring a template")
		}
		if !exists {
			return ErrNotFound
		}
		tag, err := tx.Exec(ctx, `
			DELETE FROM template_archivals WHERE tenant_id = $1 AND name = $2`,
			string(s.tenant), name)
		if err != nil {
			return wrap(err, "restoring a template")
		}
		if tag.RowsAffected() == 0 {
			return ErrConflict
		}
		return nil
	})
}

// GetTemplateArchival reports whether a template name has been withdrawn, and by whom.
//
// A missing row is the zero value and no error: every template that was never archived is this answer,
// and a caller on the enrolment path asking "may this still be issued" must not have to tell an
// ordinary state apart from a failure to read.
func (s *scopedPostgres) GetTemplateArchival(ctx context.Context, name string) (TemplateArchival, error) {
	var a TemplateArchival
	err := s.withTenant(ctx, "reading a template archival", func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT name, archived_at, archived_by
			  FROM template_archivals
			 WHERE tenant_id = $1 AND name = $2`, string(s.tenant), name,
		).Scan(&a.Name, &a.ArchivedAt, &a.ArchivedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			a = TemplateArchival{}
			return nil
		}
		return wrap(err, "reading a template archival")
	})
	if err != nil {
		return TemplateArchival{}, err
	}
	return a, nil
}

// ListTemplateVersions returns every stored revision of one template, newest first.
//
// Ordered by version rather than by creation time, because that is the number a host's bootstrap
// record carries and the one an operator is matching against; two revisions saved in the same second
// would otherwise come back in whichever order the planner chose.
func (s *scopedPostgres) ListTemplateVersions(ctx context.Context, name string) ([]TemplateRevision, error) {
	var out []TemplateRevision
	err := s.withTenant(ctx, "listing template versions", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT version, created_at, created_by,
			       (signature <> '' AND signer_key_id <> '' AND signer_algorithm <> '') AS signed,
			       signer_key_id
			  FROM templates
			 WHERE tenant_id = $1 AND name = $2
			 ORDER BY version DESC`, string(s.tenant), name)
		if err != nil {
			return wrap(err, "listing template versions")
		}
		defer rows.Close()

		for rows.Next() {
			var r TemplateRevision
			if err := rows.Scan(&r.Version, &r.CreatedAt, &r.CreatedBy, &r.Signed,
				&r.SignerKeyID); err != nil {
				return wrap(err, "scanning a template revision")
			}
			out = append(out, r)
		}
		return wrap(rows.Err(), "listing template versions")
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// GetTemplateVersion returns one version of a template, or ErrNotFound. Version 0 means the latest.
func (s *scopedPostgres) GetTemplateVersion(ctx context.Context, name string, version int) (TemplateVersion, error) {
	var t TemplateVersion
	err := s.withTenant(ctx, "reading a template", func(tx pgx.Tx) error {
		var row pgx.Row
		if version > 0 {
			row = tx.QueryRow(ctx, `
				SELECT `+templateColumns+`
				  FROM templates
				 WHERE tenant_id = $1 AND name = $2 AND version = $3`,
				string(s.tenant), name, version)
		} else {
			row = tx.QueryRow(ctx, `
				SELECT `+templateColumns+`
				  FROM templates
				 WHERE tenant_id = $1 AND name = $2
				 ORDER BY version DESC
				 LIMIT 1`,
				string(s.tenant), name)
		}
		var scanErr error
		t, scanErr = scanTemplate(row)
		return scanErr
	})
	if err != nil {
		return TemplateVersion{}, err
	}
	return t, nil
}

// GetEnrollmentToken returns one token by hash without consuming it, or ErrTokenUnusable.
//
// It reads through the tenant setting like every other scoped method, so a token issued by another
// tenant is not found rather than revealed — the same shape of answer ConsumeEnrollmentToken gives,
// one statement earlier. The usability conditions live in the WHERE clause, against the database's
// clock, exactly as TenantForEnrollmentToken checks them and for the same reason: the interface hands
// this method no other clock, and a token within a skew of its deadline fails at consumption anyway.
func (s *scopedPostgres) GetEnrollmentToken(ctx context.Context, hash string) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := s.withTenant(ctx, "reading an enrolment token", func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT hash, label, fleet_group, bootstrap, created_at, expires_at
			  FROM enrollment_tokens
			 WHERE hash = $1 AND tenant_id = $2
			   AND consumed_at IS NULL
			   AND expires_at > now()`,
			hash, string(s.tenant),
		).Scan(&t.Hash, &t.Label, &t.Group, &t.Bootstrap, &t.CreatedAt, &t.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenUnusable
		}
		return wrap(err, "reading an enrolment token")
	})
	if err != nil {
		return EnrollmentToken{}, err
	}
	return t, nil
}
