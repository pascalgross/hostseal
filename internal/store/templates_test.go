package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestTemplateVersionsAccumulate proves that saving is superseding, never overwriting.
//
// The property under test is the one the Tier 2 bootstrap record depends on: a version, once written,
// resolves to the same bytes for ever, and a change arrives as the next number.
func TestTemplateVersionsAccumulate(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		first, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("sealed-v1"),
			CreatedAt: time.Now().UTC(), CreatedBy: "test:alice",
		})
		if err != nil || first != 1 {
			t.Fatalf("first version: %d, %v", first, err)
		}
		second, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("sealed-v2"),
			Signature: "c2ln", SignerKeyID: "ops-laptop", SignerAlgorithm: "ed25519",
			CreatedAt: time.Now().UTC(), CreatedBy: "test:bob",
		})
		if err != nil || second != 2 {
			t.Fatalf("second version: %d, %v", second, err)
		}

		v1, err := tenant.GetTemplateVersion(ctx, "standard-server", 1)
		if err != nil || string(v1.BodySealed) != "sealed-v1" {
			t.Fatalf("version 1 did not survive being superseded: %+v, %v", v1, err)
		}
		if v1.Signed() {
			t.Fatal("version 1 reports itself signed with no signature")
		}
		latest, err := tenant.GetTemplateVersion(ctx, "standard-server", 0)
		if err != nil || latest.Version != 2 || string(latest.BodySealed) != "sealed-v2" {
			t.Fatalf("latest is not version 2: %+v, %v", latest, err)
		}
		if !latest.Signed() || latest.SignerKeyID != "ops-laptop" {
			t.Fatalf("the signature did not survive storage: %+v", latest)
		}
	})
}

// TestTemplateListingShowsTheLatestVersionPerName proves the listing is a summary, not a history.
func TestTemplateListingShowsTheLatestVersionPerName(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		base := time.Now().UTC().Add(-time.Hour)
		for i, save := range []TemplateVersion{
			{Name: "standard-server", BodySealed: []byte("a1"), CreatedBy: "test:alice"},
			{Name: "database", BodySealed: []byte("b1"), CreatedBy: "test:alice"},
			{Name: "standard-server", BodySealed: []byte("a2"), CreatedBy: "test:bob",
				Signature: "c2ln", SignerKeyID: "ops-laptop", SignerAlgorithm: "ed25519"},
		} {
			save.CreatedAt = base.Add(time.Duration(i) * time.Minute)
			if _, err := tenant.CreateTemplateVersion(ctx, save); err != nil {
				t.Fatalf("saving %s: %v", save.Name, err)
			}
		}

		listed, err := tenant.ListTemplates(ctx, false)
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 2 {
			t.Fatalf("listed %d templates, want 2: %+v", len(listed), listed)
		}
		// Newest latest-version first: standard-server's v2 postdates database's v1.
		if listed[0].Name != "standard-server" || listed[0].LatestVersion != 2 ||
			!listed[0].Signed || listed[0].CreatedBy != "test:bob" {
			t.Fatalf("first summary is wrong: %+v", listed[0])
		}
		if listed[1].Name != "database" || listed[1].LatestVersion != 1 || listed[1].Signed {
			t.Fatalf("second summary is wrong: %+v", listed[1])
		}
	})
}

// TestTemplateLookupMissesAreErrNotFound proves the sentinel, which is what handlers map to a 404.
func TestTemplateLookupMissesAreErrNotFound(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		if _, err := tenant.GetTemplateVersion(ctx, "absent", 0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing name returned %v", err)
		}
		if _, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("v1"), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("saving: %v", err)
		}
		if _, err := tenant.GetTemplateVersion(ctx, "standard-server", 7); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing version returned %v", err)
		}
	})
}

// TestArchivingWithdrawsANameAndKeepsEveryVersion is the central property of archiving.
//
// It is why archiving exists rather than a delete. An operator retiring a template wants the name out
// of use; a host that was bootstrapped from it still has a record naming a version, and docs/SECURITY.md
// §7 says that record has to resolve to the bytes that ran. Both halves are asserted here, because
// either one alone is a different feature: hiding without keeping is a delete with extra steps, and
// keeping without hiding is what the page already did.
func TestArchivingWithdrawsANameAndKeepsEveryVersion(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		for _, sealed := range []string{"v1", "v2"} {
			if _, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
				Name: "standard-server", BodySealed: []byte(sealed),
				CreatedAt: time.Now().UTC(), CreatedBy: "test:alice",
			}); err != nil {
				t.Fatalf("saving %s: %v", sealed, err)
			}
		}

		at := time.Now().UTC().Truncate(time.Second)
		if err := tenant.ArchiveTemplate(ctx, TemplateArchival{
			Name: "standard-server", ArchivedAt: at, ArchivedBy: "test:bob",
		}); err != nil {
			t.Fatalf("archiving: %v", err)
		}

		// Gone from the listing an operator reads every day.
		listed, err := tenant.ListTemplates(ctx, false)
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 0 {
			t.Fatalf("an archived template is still in the default listing: %+v", listed)
		}

		// Present, and marked, when asked for — otherwise nobody could restore it.
		withArchived, err := tenant.ListTemplates(ctx, true)
		if err != nil {
			t.Fatalf("listing with archived: %v", err)
		}
		if len(withArchived) != 1 || !withArchived[0].Archived ||
			withArchived[0].ArchivedBy != "test:bob" {
			t.Fatalf("the archived template is not listed as archived: %+v", withArchived)
		}
		if !withArchived[0].ArchivedAt.Equal(at) {
			t.Errorf("archived at %v, want %v", withArchived[0].ArchivedAt, at)
		}
		if withArchived[0].LatestVersion != 2 {
			t.Errorf("the summary lost its version number: %+v", withArchived[0])
		}

		// And every version still resolves, which is the half a delete could not offer.
		for version, want := range map[int]string{1: "v1", 2: "v2"} {
			got, err := tenant.GetTemplateVersion(ctx, "standard-server", version)
			if err != nil || string(got.BodySealed) != want {
				t.Fatalf("version %d of an archived template: %+v, %v", version, got, err)
			}
		}
		revisions, err := tenant.ListTemplateVersions(ctx, "standard-server")
		if err != nil || len(revisions) != 2 {
			t.Fatalf("the revision history of an archived template: %+v, %v", revisions, err)
		}

		archival, err := tenant.GetTemplateArchival(ctx, "standard-server")
		if err != nil || !archival.Archived() || archival.ArchivedBy != "test:bob" {
			t.Fatalf("reading the archival back: %+v, %v", archival, err)
		}
	})
}

// TestRestoringPutsATemplateBackUnchanged proves the undo is complete and adds nothing.
//
// The "unchanged" half matters as much as the "back" half: restoring must not renumber, re-sign or
// otherwise alter a version, because a restore that produced a v3 would make the archival a way to
// edit a template after the fact.
func TestRestoringPutsATemplateBackUnchanged(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		if _, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("v1"),
			Signature: "c2ln", SignerKeyID: "ops-laptop", SignerAlgorithm: "ed25519",
			CreatedAt: time.Now().UTC(), CreatedBy: "test:alice",
		}); err != nil {
			t.Fatalf("saving: %v", err)
		}
		if err := tenant.ArchiveTemplate(ctx, TemplateArchival{
			Name: "standard-server", ArchivedAt: time.Now().UTC(), ArchivedBy: "test:bob",
		}); err != nil {
			t.Fatalf("archiving: %v", err)
		}
		if err := tenant.RestoreTemplate(ctx, "standard-server"); err != nil {
			t.Fatalf("restoring: %v", err)
		}

		listed, err := tenant.ListTemplates(ctx, false)
		if err != nil {
			t.Fatalf("listing: %v", err)
		}
		if len(listed) != 1 || listed[0].Archived || listed[0].LatestVersion != 1 ||
			!listed[0].Signed || listed[0].CreatedBy != "test:alice" {
			t.Fatalf("a restored template came back different: %+v", listed)
		}
		if !listed[0].ArchivedAt.IsZero() || listed[0].ArchivedBy != "" {
			t.Errorf("a restored template still carries an archival: %+v", listed[0])
		}
		archival, err := tenant.GetTemplateArchival(ctx, "standard-server")
		if err != nil || archival.Archived() {
			t.Fatalf("the archival survived the restore: %+v, %v", archival, err)
		}

		// A second save still numbers from the history, which is what "nothing was destroyed" means
		// for the one thing an archival could plausibly have reset.
		next, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("v2"),
			CreatedAt: time.Now().UTC(), CreatedBy: "test:alice",
		})
		if err != nil || next != 2 {
			t.Fatalf("the version after a restore was numbered %d: %v", next, err)
		}
	})
}

// TestArchivingRefusesTheStatesItIsAlreadyIn pins the two sentinels handlers map to 404 and 409.
//
// They are told apart deliberately. A client acting on a listing it read a minute ago has to learn
// that it was stale rather than be told its request succeeded, because "archive" and "restore" are
// each other's undo and a silent no-op is how two operators end up disagreeing about which.
func TestArchivingRefusesTheStatesItIsAlreadyIn(t *testing.T) {
	eachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tenant := testTenant(t, s, "alpha", ApprovalNone)

		archival := TemplateArchival{
			Name: "absent", ArchivedAt: time.Now().UTC(), ArchivedBy: "test:alice",
		}
		if err := tenant.ArchiveTemplate(ctx, archival); !errors.Is(err, ErrNotFound) {
			t.Fatalf("archiving a name nobody stored returned %v", err)
		}
		if err := tenant.RestoreTemplate(ctx, "absent"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("restoring a name nobody stored returned %v", err)
		}
		// And a name with no versions reads as live rather than as an error, because that is what
		// every template that was never archived reads as.
		if a, err := tenant.GetTemplateArchival(ctx, "absent"); err != nil || a.Archived() {
			t.Fatalf("an absent template's archival: %+v, %v", a, err)
		}

		if _, err := tenant.CreateTemplateVersion(ctx, TemplateVersion{
			Name: "standard-server", BodySealed: []byte("v1"), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("saving: %v", err)
		}
		if err := tenant.RestoreTemplate(ctx, "standard-server"); !errors.Is(err, ErrConflict) {
			t.Fatalf("restoring a live template returned %v", err)
		}

		archival.Name = "standard-server"
		if err := tenant.ArchiveTemplate(ctx, archival); err != nil {
			t.Fatalf("archiving: %v", err)
		}
		if err := tenant.ArchiveTemplate(ctx, archival); !errors.Is(err, ErrConflict) {
			t.Fatalf("archiving an archived template returned %v", err)
		}
	})
}
