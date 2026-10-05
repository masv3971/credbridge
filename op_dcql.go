package credbridge

import (
	"errors"
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// isValidDCQLID reports whether s is a non-empty string using only the
// character set OpenID4VP §6.1 permits for DCQL id values.
func isValidDCQLID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// buildResolvedDCQL implements the Appendix A scope→DCQL translation
// and the Appendix A.2 augmentation of an RP-supplied DCQL query.
// credentialSetIDs supplies the RFC §4.1.2 Credential Set "id" values
// aligned index-wise with rp.CredentialSets.
func (o *OP) buildResolvedDCQL(scopes []string, rp *openid4vp.DCQL, credentialSetIDs []string) (ResolvedDCQL, error) {
	if rp == nil {
		return o.buildScopeDCQL(scopes)
	}
	covered := make(map[string]bool)
	typeToScope := make(map[string]string, len(o.cfg.CredentialPresentations))
	for scope, cfg := range o.cfg.CredentialPresentations {
		typeToScope[typeKey(cfg.Format, cfg.Type)] = scope
	}
	resolvedDCQL := ResolvedDCQL{}
	for _, cq := range rp.Credentials {
		key, err := metaTypeKey(cq)
		if err != nil {
			return ResolvedDCQL{}, err
		}
		scope, ok := typeToScope[key]
		if !ok {
			return ResolvedDCQL{}, fmt.Errorf("%w: unsupported credential type in dcql_query", ErrOPInvalidRequest)
		}
		covered[scope] = true
		resolvedDCQL.Credentials = append(resolvedDCQL.Credentials, resolveCredentialQuery(cq, scope))
	}
	if len(rp.CredentialSets) > 0 {
		if err := validateCredentialSetIDs(rp.CredentialSets, credentialSetIDs); err != nil {
			return ResolvedDCQL{}, err
		}
	}
	for i, cs := range rp.CredentialSets {
		resolvedDCQL.CredentialSets = append(resolvedDCQL.CredentialSets, ResolvedCredentialSet{
			ID:       credentialSetIDs[i],
			Options:  cloneOptions(cs.Options),
			Required: cs.IsRequired(),
		})
	}
	// Augment: add a scope-derived Credential Query for every uncovered
	// scope, with an id prefixed by BridgeIDPrefix per Appendix A.2.
	for _, scope := range scopes {
		if covered[scope] {
			continue
		}
		id := BridgeIDPrefix + scope
		if !isValidDCQLID(id) {
			return ResolvedDCQL{}, fmt.Errorf("%w: scope %q would produce a DCQL id violating OpenID4VP \u00a76.1 charset", ErrOPInvalidRequest, scope)
		}
		aug := o.credentialQueryForScope(scope, id)
		resolvedDCQL.Credentials = append(resolvedDCQL.Credentials, resolveCredentialQuery(aug, scope))
	}
	return resolvedDCQL, nil
}

// validateCredentialSetIDs enforces §4.1.2's REQUIRED "id" on every
// credential_sets entry: aligned count, non-empty, DCQL charset,
// unique per response.
func validateCredentialSetIDs(sets []openid4vp.CredentialSetQuery, ids []string) error {
	if len(ids) < len(sets) {
		return fmt.Errorf("%w: credential_sets entries missing id (need %d, got %d)", ErrOPInvalidRequest, len(sets), len(ids))
	}
	seen := make(map[string]struct{}, len(sets))
	for i := range sets {
		id := ids[i]
		if !isValidDCQLID(id) {
			return fmt.Errorf("%w: credential_sets[%d].id %q missing or violates OpenID4VP \u00a76.1 charset", ErrOPInvalidRequest, i, id)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: credential_sets ids must be unique; %q appears twice", ErrOPInvalidRequest, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// buildScopeDCQL translates a set of credential type scopes into a
// ResolvedDCQL per Appendix A.1 (Scope-Based Mode).
func (o *OP) buildScopeDCQL(scopes []string) (ResolvedDCQL, error) {
	if len(scopes) == 0 {
		return ResolvedDCQL{}, errors.New("credbridge/op: no scopes")
	}
	resolvedDCQL := ResolvedDCQL{}
	for _, scope := range scopes {
		if !isValidDCQLID(scope) {
			return ResolvedDCQL{}, fmt.Errorf("%w: scope %q violates OpenID4VP \u00a76.1 DCQL id charset", ErrOPInvalidRequest, scope)
		}
		aug := o.credentialQueryForScope(scope, scope)
		resolvedDCQL.Credentials = append(resolvedDCQL.Credentials, resolveCredentialQuery(aug, scope))
	}
	return resolvedDCQL, nil
}

// credentialQueryForScope materialises a CredentialQuery from a
// pre-registered scope entry per Appendix A.1.
func (o *OP) credentialQueryForScope(scope, id string) openid4vp.CredentialQuery {
	cfg := o.cfg.CredentialPresentations[scope]
	q := openid4vp.CredentialQuery{
		ID:     id,
		Format: cfg.Format,
	}
	switch cfg.Format {
	case openid4vp.FormatSDJWTVC:
		q.Meta = openid4vp.MetaQuery{VCTValues: append([]string(nil), cfg.Type...)}
	case openid4vp.FormatMsoMdoc:
		if len(cfg.Type) > 0 {
			q.Meta = openid4vp.MetaQuery{DoctypeValue: cfg.Type[0]}
		}
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		q.Meta = openid4vp.MetaQuery{TypeValues: [][]string{append([]string(nil), cfg.Type...)}}
	}
	for _, path := range cfg.Claims {
		q.Claims = append(q.Claims, openid4vp.ClaimQuery{Path: openid4vp.StringPath(path...)})
	}
	return q
}

// resolveCredentialQuery captures the RP's CredentialQuery in the form
// the OP consults at response time (paths, values, claim_sets).
func resolveCredentialQuery(cq openid4vp.CredentialQuery, scope string) ResolvedCredentialQuery {
	resolvedQuery := ResolvedCredentialQuery{
		ID:        cq.ID,
		Scope:     scope,
		Format:    cq.Format,
		ClaimSets: cloneOptions(cq.ClaimSet),
	}
	switch cq.Format {
	case openid4vp.FormatSDJWTVC:
		resolvedQuery.Type = append([]string(nil), cq.Meta.VCTValues...)
	case openid4vp.FormatMsoMdoc:
		if cq.Meta.DoctypeValue != "" {
			resolvedQuery.Type = []string{cq.Meta.DoctypeValue}
		}
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		if len(cq.Meta.TypeValues) > 0 {
			resolvedQuery.Type = append([]string(nil), cq.Meta.TypeValues[0]...)
		}
	}
	for _, cl := range cq.Claims {
		resolvedQuery.Claims = append(resolvedQuery.Claims, ResolvedClaim{
			ID:     cl.ID,
			Path:   stringPath(cl.Path),
			Values: append([]any(nil), cl.Values...),
		})
	}
	return resolvedQuery
}

// stringPath converts an openid4vp claim path ([]*string) into a
// []string, mapping nil (JSON null) elements to empty strings.
func stringPath(path []*string) []string {
	out := make([]string, 0, len(path))
	for _, p := range path {
		if p == nil {
			out = append(out, "")
			continue
		}
		out = append(out, *p)
	}
	return out
}

// cloneOptions returns a deep copy of a DCQL options / claim_sets
// alternation slice.
func cloneOptions(in [][]string) [][]string {
	if in == nil {
		return nil
	}
	out := make([][]string, len(in))
	for i, opt := range in {
		out[i] = append([]string(nil), opt...)
	}
	return out
}
