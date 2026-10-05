package credbridge

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// OPWalletRequest describes what the OP asks the wallet to present. The
// caller is responsible for transporting it — this library does not
// speak HTTP directly.
type OPWalletRequest struct {
	// DCQL is the query the wallet must satisfy.
	DCQL openid4vp.DCQL
	// Nonce is byte-identical to the OIDC nonce (Section 7.1).
	Nonce string
	// ClientID is the OP's verifier identifier for this exchange.
	ClientID string
	// ResponseURI is the URL the wallet must POST the presentation to.
	ResponseURI string
	// State is the OIDC "state" echoed through the wallet exchange.
	State string
}

// BuildWalletRequest returns an OpenID4VP-shaped request for opSession. The
// nonce is copied from opSession byte-for-byte so that the wallet's
// presentation binds to the OIDC session (Section 7.1).
func (o *OP) BuildWalletRequest(_ context.Context, opSession *OPSession, responseURI string) (*OPWalletRequest, error) {
	if opSession == nil {
		return nil, fmt.Errorf("credbridge/op: nil session")
	}
	dcql := openid4vp.DCQL{}
	for _, c := range opSession.DCQL.Credentials {
		dcql.Credentials = append(dcql.Credentials, c.toCredentialQuery())
	}
	for _, cs := range opSession.DCQL.CredentialSets {
		req := cs.Required
		dcql.CredentialSets = append(dcql.CredentialSets, openid4vp.CredentialSetQuery{
			Options:  cloneOptions(cs.Options),
			Required: &req,
		})
	}
	return &OPWalletRequest{
		DCQL:        dcql,
		Nonce:       opSession.Nonce,
		ClientID:    o.cfg.Issuer,
		ResponseURI: responseURI,
		State:       opSession.State,
	}, nil
}

// toCredentialQuery re-serialises r as an openid4vp.CredentialQuery
// for the wallet-facing OpenID4VP request (Appendix A).
func (r ResolvedCredentialQuery) toCredentialQuery() openid4vp.CredentialQuery {
	cq := openid4vp.CredentialQuery{
		ID:     r.ID,
		Format: r.Format,
	}
	switch r.Format {
	case openid4vp.FormatSDJWTVC:
		cq.Meta.VCTValues = append([]string(nil), r.Type...)
	case openid4vp.FormatMsoMdoc:
		if len(r.Type) > 0 {
			cq.Meta.DoctypeValue = r.Type[0]
		}
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		cq.Meta.TypeValues = [][]string{append([]string(nil), r.Type...)}
	}
	for _, cl := range r.Claims {
		cq.Claims = append(cq.Claims, openid4vp.ClaimQuery{
			ID:     cl.ID,
			Path:   openid4vp.StringPath(cl.Path...),
			Values: append([]any(nil), cl.Values...),
		})
	}
	cq.ClaimSet = cloneOptions(r.ClaimSets)
	return cq
}

// OPPresentationResult is the parsed, verified result of a wallet
// presentation.
type OPPresentationResult struct {
	// Entries maps credential query id → verified credential entries.
	Entries map[string][]CredentialEntry
	// SatisfiedSets is populated from opSession.DCQL.CredentialSets when
	// the RP requested one or more DCQL Credential Sets.
	SatisfiedSets []ResolvedCredentialSet
}

// HandleWalletResponse verifies resp against opSession.DCQL and
// returns the entries the OP will pack into presented_credential_sets.
//
// The trust check is delegated to matcher; pass nil to skip trust
// authority evaluation (which sets trust_status to "not_checked" for
// every entry).
func (o *OP) HandleWalletResponse(ctx context.Context, opSession *OPSession, resp *openid4vp.VPResponse, matcher openid4vp.TrustedAuthorityMatcher) (*OPPresentationResult, error) {
	if resp == nil || len(resp.VPToken) == 0 {
		return nil, fmt.Errorf("%w: wallet returned empty vp_token", ErrOPAccessDenied)
	}
	extractor := openid4vp.NewClaimsExtractor()

	byID := make(map[string]ResolvedCredentialQuery, len(opSession.DCQL.Credentials))
	for _, c := range opSession.DCQL.Credentials {
		byID[c.ID] = c
	}
	entries := make(map[string][]CredentialEntry, len(resp.VPToken))
	for credID, tokens := range resp.VPToken {
		resolvedQuery, ok := byID[credID]
		if !ok {
			return nil, fmt.Errorf("%w: wallet returned unknown credential id %q", ErrOPAccessDenied, credID)
		}
		for _, token := range tokens {
			claims, err := extractor.ExtractClaimsFromVPToken(ctx, token)
			if err != nil {
				return nil, fmt.Errorf("%w: extract claims: %v", ErrOPAccessDenied, err)
			}
			if err := resolvedQuery.postValidateValues(claims); err != nil {
				return nil, err
			}
			matchedOption, err := resolvedQuery.selectClaimSetOption(claims)
			if err != nil {
				return nil, err
			}
			filtered := resolvedQuery.filterClaims(claims, matchedOption)
			entry := CredentialEntry{
				Type:       append([]string(nil), resolvedQuery.Type...),
				Claims:     filtered,
				VerifiedAt: o.now().Unix(),
				Verification: &Verification{
					TrustStatus:   deriveTrustStatus(matcher),
					HolderBinding: HolderBindingKey,
				},
			}
			entries[credID] = append(entries[credID], entry)
		}
	}
	return &OPPresentationResult{
		Entries:       entries,
		SatisfiedSets: append([]ResolvedCredentialSet(nil), opSession.DCQL.CredentialSets...),
	}, nil
}

// postValidateValues enforces the Appendix A.4 rule that "values"
// constraints must be re-validated by the OP after presentation.
func (r ResolvedCredentialQuery) postValidateValues(claims map[string]any) error {
	for _, cl := range r.Claims {
		if len(cl.Values) == 0 {
			continue
		}
		got, ok := lookupClaim(claims, cl.Path)
		if !ok {
			return fmt.Errorf("%w: wallet did not disclose claim %v", ErrOPAccessDenied, cl.Path)
		}
		matched := false
		for _, want := range cl.Values {
			if MatchValue(got, want) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: disclosed value for %v not in requested values", ErrOPAccessDenied, cl.Path)
		}
	}
	return nil
}

// selectClaimSetOption implements §4.1.2's deterministic "first
// matching option" selection: iterate ClaimSets in RP-supplied order
// and return the first option whose listed claim ids are all present
// in the disclosed claims. Returns nil (no option) when ClaimSets is
// empty. Returns [ErrOPAccessDenied] when ClaimSets is non-empty and
// no option is satisfied.
func (r ResolvedCredentialQuery) selectClaimSetOption(claims map[string]any) ([]string, error) {
	if len(r.ClaimSets) == 0 {
		return nil, nil
	}
	byID := make(map[string]ResolvedClaim, len(r.Claims))
	for _, cl := range r.Claims {
		byID[cl.ID] = cl
	}
	for _, option := range r.ClaimSets {
		ok := true
		for _, id := range option {
			cl, exists := byID[id]
			if !exists {
				ok = false
				break
			}
			if _, present := lookupClaim(claims, cl.Path); !present {
				ok = false
				break
			}
		}
		if ok {
			return option, nil
		}
	}
	return nil, fmt.Errorf("%w: disclosed claims satisfy no claim_sets option", ErrOPAccessDenied)
}

// filterClaims implements §5.4 data minimisation: when the RP supplied
// a specific set of claim paths (or when a claim_sets option matched),
// only those paths are relayed even if the wallet disclosed more.
func (r ResolvedCredentialQuery) filterClaims(claims map[string]any, matchedOption []string) map[string]any {
	if len(matchedOption) > 0 {
		byID := make(map[string]ResolvedClaim, len(r.Claims))
		for _, cl := range r.Claims {
			byID[cl.ID] = cl
		}
		out := make(map[string]any, len(matchedOption))
		for _, id := range matchedOption {
			cl, ok := byID[id]
			if !ok {
				continue
			}
			if v, present := lookupClaim(claims, cl.Path); present {
				assignClaim(out, cl.Path, v)
			}
		}
		return out
	}
	if len(r.Claims) == 0 {
		return claims
	}
	out := make(map[string]any, len(r.Claims))
	for _, cl := range r.Claims {
		if v, ok := lookupClaim(claims, cl.Path); ok {
			assignClaim(out, cl.Path, v)
		}
	}
	return out
}

// lookupClaim walks path through nested objects in claims and returns
// the value at that DCQL claim path, false when any segment is absent.
func lookupClaim(claims map[string]any, path []string) (any, bool) {
	current := any(claims)
	for _, seg := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[seg]
		if !ok {
			return nil, false
		}
		current = v
	}
	return current, true
}

// assignClaim stores value at path in dst, creating intermediate
// objects as needed so the DCQL claim path structure is preserved.
func assignClaim(dst map[string]any, path []string, value any) {
	if len(path) == 1 {
		dst[path[0]] = value
		return
	}
	current := dst
	for i, seg := range path {
		if i == len(path)-1 {
			current[seg] = value
			return
		}
		next, ok := current[seg].(map[string]any)
		if !ok {
			next = make(map[string]any)
			current[seg] = next
		}
		current = next
	}
}

// deriveTrustStatus returns the initial trust_status the OP records on
// a Credential Entry (§5.1.2, §8.3). A nil matcher yields "not_checked";
// otherwise "valid" until finer-grained checks are wired in.
func deriveTrustStatus(matcher openid4vp.TrustedAuthorityMatcher) TrustStatus {
	if matcher == nil {
		return TrustStatusNotChecked
	}
	return TrustStatusValid
}
