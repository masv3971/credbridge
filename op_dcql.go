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
		resolved, err := o.resolveCredentialQuery(cq, scope)
		if err != nil {
			return ResolvedDCQL{}, err
		}
		resolvedDCQL.Credentials = append(resolvedDCQL.Credentials, resolved)
	}
	if len(rp.CredentialSets) > 0 {
		if err := validateCredentialSetIDs(rp.CredentialSets, credentialSetIDs); err != nil {
			return ResolvedDCQL{}, err
		}
		if err := validateCredentialSetOptions(rp.CredentialSets, rp.Credentials); err != nil {
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
		resolved, err := o.resolveCredentialQuery(aug, scope)
		if err != nil {
			return ResolvedDCQL{}, err
		}
		resolvedDCQL.Credentials = append(resolvedDCQL.Credentials, resolved)
	}
	return resolvedDCQL, nil
}

// validateCredentialSetOptions enforces that every credential_sets
// option is non-empty and references a credential query id that exists
// in credentials, so a malformed request is rejected with
// invalid_request at authorization time rather than surfacing later as
// an unsatisfied presentation.
func validateCredentialSetOptions(sets []openid4vp.CredentialSetQuery, credentials []openid4vp.CredentialQuery) error {
	credIDs := make(map[string]struct{}, len(credentials))
	for _, cq := range credentials {
		credIDs[cq.ID] = struct{}{}
	}
	for i, cs := range sets {
		if len(cs.Options) == 0 {
			return fmt.Errorf("%w: credential_sets[%d] has no options", ErrOPInvalidRequest, i)
		}
		for _, option := range cs.Options {
			if len(option) == 0 {
				return fmt.Errorf("%w: credential_sets[%d] has an empty option", ErrOPInvalidRequest, i)
			}
			for _, ref := range option {
				if _, ok := credIDs[ref]; !ok {
					return fmt.Errorf("%w: credential_sets[%d] option references unknown credential query id %q", ErrOPInvalidRequest, i, ref)
				}
			}
		}
	}
	return nil
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
		resolved, err := o.resolveCredentialQuery(aug, scope)
		if err != nil {
			return ResolvedDCQL{}, err
		}
		resolvedDCQL.Credentials = append(resolvedDCQL.Credentials, resolved)
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
// the OP consults at response time (paths, values, claim_sets, trusted
// authorities, holder binding). When the RP omits claims, the scope's
// pre-registered claim set is applied so response filtering cannot
// over-disclose. Trusted authorities are filtered through the OP's SSRF
// allowlist (§7.4).
func (o *OP) resolveCredentialQuery(cq openid4vp.CredentialQuery, scope string) (ResolvedCredentialQuery, error) {
	resolvedQuery := ResolvedCredentialQuery{
		ID:                                cq.ID,
		Scope:                             scope,
		Format:                            cq.Format,
		ClaimSets:                         cloneOptions(cq.ClaimSet),
		RequireCryptographicHolderBinding: cq.RequiresCryptographicHolderBinding(),
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
	// §5.4 / Appendix A: an omitted claims member in DCQL mode must fall
	// back to the scope's pre-registered claim set, not "relay everything".
	if len(resolvedQuery.Claims) == 0 {
		if cfg, ok := o.cfg.CredentialPresentations[scope]; ok {
			for _, path := range cfg.Claims {
				resolvedQuery.Claims = append(resolvedQuery.Claims, ResolvedClaim{
					Path: append([]string(nil), path...),
				})
			}
		}
	}
	kept, allowed, err := o.filterTrustedAuthorities(cq.TrustedAuthorities)
	if err != nil {
		return ResolvedCredentialQuery{}, err
	}
	resolvedQuery.TrustedAuthorities = kept
	resolvedQuery.TrustedAuthorityAllowed = allowed
	return resolvedQuery, nil
}

// filterTrustedAuthorities applies the OP's SSRF allowlist (§7.4) to an
// RP-supplied trusted_authorities array. Each authority value is kept
// only when present in TrustedAuthorityAllowlist. When the RP supplied
// authorities but none survive filtering, the request is rejected with
// invalid_request per §7.4 (all authorities off-allowlist). A query with
// no trusted_authorities is unconstrained.
func (o *OP) filterTrustedAuthorities(auths []openid4vp.TrustedAuthority) ([]openid4vp.TrustedAuthority, bool, error) {
	if len(auths) == 0 {
		return nil, false, nil
	}
	var kept []openid4vp.TrustedAuthority
	for _, a := range auths {
		var vals []string
		for _, v := range a.Values {
			if o.cfg.TrustedAuthorityAllowlist[v] {
				vals = append(vals, v)
			}
		}
		if len(vals) > 0 {
			kept = append(kept, openid4vp.TrustedAuthority{Type: a.Type, Values: vals})
		}
	}
	if len(kept) == 0 {
		return nil, false, fmt.Errorf("%w: all trusted_authorities are off the OP allowlist", ErrOPInvalidRequest)
	}
	return kept, true, nil
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
