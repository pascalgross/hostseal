package store

import (
	"context"
	"sort"
	"time"
)

// templateKey identifies one template version the way the schema does, by tenant, name and version.
//
// The tenant is in the key rather than in a check the caller remembers to make, for the same reason
// jobKey carries one: two tenants naming a template "standard-server" is ordinary, and a store keyed on
// the name alone would hand one customer's provisioning secrets to the other.
type templateKey struct {
	// tenant owns the template.
	tenant TenantID

	// name is the template's identifier within its tenant.
	name string

	// version numbers this revision.
	version int
}

// templateNameKey identifies one template *name* within a tenant, which is what an archival is about.
//
// A second key type rather than templateKey with version 0, because "the name" and "version zero" are
// different things and a sentinel version would be one typo away from a lookup that silently matched a
// version row. The tenant is in it for the reason it is in templateKey: two fleets naming a template
// "standard-server" is ordinary.
type templateNameKey struct {
	// tenant owns the template.
	tenant TenantID

	// name is the template's identifier within its tenant.
	name string
}

// CreateTemplateVersion stores the next version of a template and returns the number it was given.
//
// The scan for the current maximum runs under the store's one lock, so the assignment is atomic here
// the way the single INSERT statement makes it atomic in PostgreSQL — concurrent savers get distinct
// numbers and nothing is ever overwritten.
func (s *scopedMemory) CreateTemplateVersion(_ context.Context, t TemplateVersion) (int, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if _, ok := s.store.tenants[s.tenant]; !ok {
		return 0, errUnknownTenant(s.tenant)
	}

	next := 1
	for key := range s.store.templates {
		if key.tenant == s.tenant && key.name == t.Name && key.version >= next {
			next = key.version + 1
		}
	}
	t.Version = next
	s.store.templates[templateKey{tenant: s.tenant, name: t.Name, version: next}] = t
	return next, nil
}

// ListTemplates returns one summary per template name, newest latest-version first.
//
// Archived names are filtered here rather than by the caller, matching the PostgreSQL statement: a
// listing that returned them and relied on every reader to drop them would put the retired template
// back on screen the first time a reader forgot.
func (s *scopedMemory) ListTemplates(_ context.Context, includeArchived bool) ([]TemplateSummary, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	latest := map[string]TemplateVersion{}
	for key, t := range s.store.templates {
		if key.tenant != s.tenant {
			continue
		}
		if held, ok := latest[key.name]; !ok || t.Version > held.Version {
			latest[key.name] = t
		}
	}

	out := make([]TemplateSummary, 0, len(latest))
	for _, t := range latest {
		archival := s.store.archivedTemplates[templateNameKey{tenant: s.tenant, name: t.Name}]
		if archival.Archived() && !includeArchived {
			continue
		}
		out = append(out, TemplateSummary{
			Name:          t.Name,
			LatestVersion: t.Version,
			CreatedAt:     t.CreatedAt,
			CreatedBy:     t.CreatedBy,
			Signed:        t.Signed(),
			Archived:      archival.Archived(),
			ArchivedAt:    archival.ArchivedAt,
			ArchivedBy:    archival.ArchivedBy,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		// The tiebreak keeps the order deterministic when a test creates two templates inside one
		// clock tick, which happens constantly and would otherwise flake by map order.
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// ListTemplateVersions returns every stored revision of one template, newest first.
func (s *scopedMemory) ListTemplateVersions(_ context.Context, name string) ([]TemplateRevision, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	var out []TemplateRevision
	for key, t := range s.store.templates {
		if key.tenant != s.tenant || key.name != name {
			continue
		}
		out = append(out, TemplateRevision{
			Version:     t.Version,
			CreatedAt:   t.CreatedAt,
			CreatedBy:   t.CreatedBy,
			Signed:      t.Signed(),
			SignerKeyID: t.SignerKeyID,
		})
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

// GetTemplateVersion returns one version of a template, or ErrNotFound. Version 0 means the latest.
func (s *scopedMemory) GetTemplateVersion(_ context.Context, name string, version int) (TemplateVersion, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if version > 0 {
		t, ok := s.store.templates[templateKey{tenant: s.tenant, name: name, version: version}]
		if !ok {
			return TemplateVersion{}, ErrNotFound
		}
		return t, nil
	}

	var found TemplateVersion
	var any bool
	for key, t := range s.store.templates {
		if key.tenant == s.tenant && key.name == name && (!any || t.Version > found.Version) {
			found, any = t, true
		}
	}
	if !any {
		return TemplateVersion{}, ErrNotFound
	}
	return found, nil
}

// ArchiveTemplate withdraws a template name from use, leaving every stored version intact.
//
// Nothing is deleted from the version map here, and the same is true of the PostgreSQL implementation:
// a host's bootstrap record names a version, and this store has no method that could take one away.
func (s *scopedMemory) ArchiveTemplate(_ context.Context, a TemplateArchival) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if !s.hasTemplateLocked(a.Name) {
		return ErrNotFound
	}
	key := templateNameKey{tenant: s.tenant, name: a.Name}
	if s.store.archivedTemplates[key].Archived() {
		return ErrConflict
	}
	s.store.archivedTemplates[key] = a
	return nil
}

// RestoreTemplate puts an archived template name back into use.
func (s *scopedMemory) RestoreTemplate(_ context.Context, name string) error {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	if !s.hasTemplateLocked(name) {
		return ErrNotFound
	}
	key := templateNameKey{tenant: s.tenant, name: name}
	if !s.store.archivedTemplates[key].Archived() {
		return ErrConflict
	}
	delete(s.store.archivedTemplates, key)
	return nil
}

// GetTemplateArchival reports whether a template name has been withdrawn, and by whom.
//
// A name nobody archived is the zero value and no error, matching PostgreSQL's missing row.
func (s *scopedMemory) GetTemplateArchival(_ context.Context, name string) (TemplateArchival, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	return s.store.archivedTemplates[templateNameKey{tenant: s.tenant, name: name}], nil
}

// hasTemplateLocked reports whether this tenant has stored any version under a name.
//
// It is what tells "no such template" apart from "already archived", which the PostgreSQL
// implementation gets from an EXISTS in the same statement. The caller holds the lock, so the two
// halves of an archive cannot interleave with a save the way two round trips could.
func (s *scopedMemory) hasTemplateLocked(name string) bool {
	for key := range s.store.templates {
		if key.tenant == s.tenant && key.name == name {
			return true
		}
	}
	return false
}

// GetEnrollmentToken returns one token by hash without consuming it, or ErrTokenUnusable.
//
// Usability is checked here as well as at consumption, matching the PostgreSQL implementation's WHERE
// clause: the caller uses this to decide whether a bootstrap request is authorised, and an expired or
// consumed token authorises nothing. A token issued by another tenant is the same one answer as
// everywhere else.
func (s *scopedMemory) GetEnrollmentToken(_ context.Context, hash string) (EnrollmentToken, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()

	row, ok := s.store.tokens[hash]
	if !ok || row.tenant != s.tenant || !row.token.Usable(time.Now()) {
		return EnrollmentToken{}, ErrTokenUnusable
	}
	return row.token, nil
}
