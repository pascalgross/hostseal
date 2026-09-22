package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// wallboardShareColumns is the projection every share read shares, in the order scanWallboardShare
// expects.
//
// One constant rather than a copy per reader: a column added to the listing and forgotten in the
// lookup produces a share that is complete on the operator's page and
// missing its passphrase on the path that checks one, which is a difference nobody sees until the
// moment it decides whether a screen is asked for a passphrase at all.
const wallboardShareColumns = `id, secret_hash, password_hash, label, created_at,
	created_by, expires_at, last_seen_at`

// scanWallboardShare reads one share row using the wallboardShareColumns projection.
//
// last_seen_at comes through a pointer and becomes the zero time, rather than being COALESCEd to the
// epoch in SQL. `IsZero()` is what every caller asks — the listing renders "never polled" from it —
// and 1970 is not zero, so the COALESCE spelling would produce a store that disagrees with the
// in-memory one about a screen nobody has ever switched on. scanAPIToken says the same thing about
// last_used_at, and it says it because that bug shipped once.
func scanWallboardShare(row rowScanner) (WallboardShare, error) {
	var share WallboardShare
	var lastSeen *time.Time
	err := row.Scan(&share.ID, &share.SecretHash, &share.PasswordHash, &share.Label,
		&share.CreatedAt, &share.CreatedBy, &share.ExpiresAt, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return WallboardShare{}, ErrNotFound
	}
	if err != nil {
		return WallboardShare{}, wrap(err, "reading a wallboard share")
	}
	if lastSeen != nil {
		share.LastSeenAt = *lastSeen
	}
	return share, nil
}

// CreateWallboardShare records a link that publishes this fleet's status screen.
//
// The cap is in the statement rather than in a SELECT this method reads first, and that is the whole
// reason it lives in the store: a read followed by a write puts a round trip between the count and the
// insert, during which the operator in the next room publishes their own. As one conditional INSERT
// there is no such gap, and the count is evaluated against the same fleet's rows the insert is about to
// join.
//
// It is worth being exact about what that does and does not buy, because the honest limit is narrower
// than "cannot happen": under READ COMMITTED two transactions that overlap still take their snapshots
// before either commits, so both can see nineteen and the fleet can end up with twenty-one. Closing
// that would take a transaction-scoped advisory lock on the tenant, which serialises every publish for
// a bound nobody reaches — and the bound is an operability one rather than a boundary. Twenty exists so
// that the list stays something an operator can read and recognise every entry of; twenty-one, once, in
// the instant two people pressed publish together, still is.
//
// A repeated id or a secret already in the table arrives as a unique violation, which wrap turns into
// the same ErrConflict — one answer for "this fleet cannot hold another one" and "this one already
// exists", both of which the caller answers by generating a fresh share.
func (s *scopedPostgres) CreateWallboardShare(ctx context.Context, share WallboardShare) error {
	return s.withTenant(ctx, "publishing a wallboard share", func(tx pgx.Tx) error {
		var createdAt *time.Time
		if !share.CreatedAt.IsZero() {
			createdAt = &share.CreatedAt
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO wallboard_shares (tenant_id, id, secret_hash, password_hash, label,
			                              created_at, created_by, expires_at)
			SELECT $1, $2, $3, $4, $5, COALESCE($6::timestamptz, now()), $7, $8
			 WHERE (SELECT count(*) FROM wallboard_shares
			         WHERE tenant_id = $1 AND expires_at > now()) < $9`,
			string(s.tenant), share.ID, share.SecretHash, share.PasswordHash, share.Label,
			createdAt, share.CreatedBy, share.ExpiresAt, MaxWallboardSharesPerTenant)
		if err != nil {
			return wrap(err, "publishing a wallboard share")
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: this fleet already holds %d live wallboard shares",
				ErrConflict, MaxWallboardSharesPerTenant)
		}
		return nil
	})
}

// ListWallboardShares returns this fleet's shares, newest first, expired ones included.
//
// The tenant predicate is written out as well as being enforced by the policy. It is not a second
// guard: it is the index seek, and without it the plan is a scan the policy then filters.
//
// The id breaks ties, because two shares published inside one clock tick would otherwise swap places
// between page loads for a reason nobody can see — the same tiebreak the API-token listing uses.
func (s *scopedPostgres) ListWallboardShares(ctx context.Context) ([]WallboardShare, error) {
	var out []WallboardShare
	err := s.withTenant(ctx, "listing wallboard shares", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+wallboardShareColumns+`
			  FROM wallboard_shares
			 WHERE tenant_id = $1
			 ORDER BY created_at DESC, id`, string(s.tenant))
		if err != nil {
			return wrap(err, "listing wallboard shares")
		}
		defer rows.Close()

		for rows.Next() {
			share, scanErr := scanWallboardShare(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, share)
		}
		return wrap(rows.Err(), "listing wallboard shares")
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WallboardShareBySecret returns the live share whose secret hashes to this, or ErrNotFound.
//
// Liveness is a term in the predicate rather than a check afterwards, which is what keeps an unknown
// secret, a withdrawn share and an expired one one code path taking one amount of time. Three refusals
// written separately would be three things to keep matched, and the one that drifted would be the one
// that answered "expired" to somebody holding a link that was never valid.
//
// The instant comes from the caller rather than from now(), because the interface hands one in and the
// in-memory store has no database clock to reach for. Both stores therefore answer the same question,
// and the poll path keeps its window against a single clock — the reading docs/SECURITY.md §4.3 takes
// of every other validity window in HostSeal.
func (s *scopedPostgres) WallboardShareBySecret(ctx context.Context, secretHash string,
	now time.Time) (WallboardShare, error) {

	var share WallboardShare
	err := s.withTenant(ctx, "resolving a wallboard share", func(tx pgx.Tx) error {
		var scanErr error
		share, scanErr = scanWallboardShare(tx.QueryRow(ctx, `
			SELECT `+wallboardShareColumns+`
			  FROM wallboard_shares
			 WHERE tenant_id = $1 AND secret_hash = $2 AND expires_at > $3`,
			string(s.tenant), secretHash, now))
		return scanErr
	})
	if err != nil {
		return WallboardShare{}, err
	}
	return share, nil
}

// DeleteWallboardShare removes one share by id, or returns ErrNotFound.
//
// ErrNotFound rather than silence when nothing was deleted, because revoking is the one thing an
// operator does here in a hurry: "that link is gone" has to mean it, and a delete that reported success
// for a share belonging to somebody else — or for one already withdrawn by a colleague — would say so
// about a wallboard still on a wall.
func (s *scopedPostgres) DeleteWallboardShare(ctx context.Context, id string) error {
	return s.withTenant(ctx, "revoking a wallboard share", func(tx pgx.Tx) error {
		return affectOne(tx.Exec(ctx,
			`DELETE FROM wallboard_shares WHERE tenant_id = $1 AND id = $2`, string(s.tenant), id))
	})
}

// TouchWallboardShare stamps when a screen last polled one share, best effort.
//
// A share that has gone matches nothing and that is deliberately not an error, which is worth saying
// rather than leaving as an unread RowsAffected. This runs on the poll path of a screen whose link an
// operator may have revoked a second ago; the poll is about to be refused by the lookup that follows,
// and reporting the stamp's failure as well would turn one revocation into a log line per screen per
// fifteen seconds. What is being forgiven is narrow: withTenant has already refused another fleet's
// rows, so the only row this can miss is one this fleet no longer has.
func (s *scopedPostgres) TouchWallboardShare(ctx context.Context, id string, at time.Time) error {
	return s.withTenant(ctx, "stamping a wallboard share", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE wallboard_shares SET last_seen_at = $3 WHERE tenant_id = $1 AND id = $2`,
			string(s.tenant), id, at)
		return wrap(err, "stamping a wallboard share")
	})
}
