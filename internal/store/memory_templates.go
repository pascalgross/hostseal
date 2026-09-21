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
func (s *scopedMemory) ListTemplates(_ context.Context) ([]TemplateSummary, error) {
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
		out = append(out, TemplateSummary{
			Name:            t.Name,
			LatestVersion:   t.Version,
			CreatedAt:       t.CreatedAt,
			CreatedBy:       t.CreatedBy,
			Signed:          t.Signed(),
			SignerKeyID:     t.SignerKeyID,
			SignerAlgorithm: t.SignerAlgorithm,
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
			Version:         t.Version,
			CreatedAt:       t.CreatedAt,
			CreatedBy:       t.CreatedBy,
			Signed:          t.Signed(),
			SignerKeyID:     t.SignerKeyID,
			SignerAlgorithm: t.SignerAlgorithm,
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
