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
	// Forward the RP's effective constraints unchanged: without these the
	// wallet would never see trusted_authorities and an explicit
	// require_cryptographic_holder_binding:false would silently revert to
	// the OpenID4VP default of true.
	cq.TrustedAuthorities = append([]openid4vp.TrustedAuthority(nil), r.TrustedAuthorities...)
	holderBinding := r.RequireCryptographicHolderBinding
	cq.RequireCryptographicHolderBinding = &holderBinding
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
	// CredentialSetsRequested records whether the originating request
	// carried credential_sets, so assembly can distinguish "no
	// credential_sets (scope mode)" from "credential_sets requested but
	// none satisfied" and never fabricate an uncorrelated fallback set.
	CredentialSetsRequested bool
	// sessionID binds this result to the OPSession it was produced for.
	// It is unexported so a caller cannot fabricate a result and bind it
	// to an unrelated session; IssueIDToken/UserInfoPayload verify it.
	sessionID string
}

// HandleWalletResponse verifies resp against opSession.DCQL and
// returns the entries the OP will pack into presented_credential_sets.
//
// Response processing accumulates per-credential-query results: a query
// whose value or claim_sets constraints fail is treated as unsatisfied
// rather than aborting the whole response, and access_denied is returned
// only when a required credential set (or, when credential_sets is
// absent, any credential query) is left unsatisfied.
//
// NOTE: this layer does not perform issuer-signature, trust-chain, or
// holder-binding verification — the pinned openid4vp extractor only
// parses tokens. Consequently trust_status is reported as "not_checked"
// and holder_binding is not asserted; the matcher parameter is reserved
// for a future verifier and does not by itself upgrade trust_status.
// Callers MUST verify credential signatures, issuer trust, and holder
// binding before relying on the returned claims.
func (o *OP) HandleWalletResponse(ctx context.Context, opSession *OPSession, resp *openid4vp.VPResponse, matcher openid4vp.TrustedAuthorityMatcher) (*OPPresentationResult, error) {
	if opSession == nil {
		return nil, fmt.Errorf("%w: nil session", ErrOPAccessDenied)
	}
	if resp == nil || len(resp.VPToken) == 0 {
		return nil, fmt.Errorf("%w: wallet returned empty vp_token", ErrOPAccessDenied)
	}
	// §7.1: the response state MUST match the session so a wallet
	// response from another transaction cannot be processed here.
	if resp.State != opSession.State {
		return nil, fmt.Errorf("%w: response state does not match session", ErrOPAccessDenied)
	}
	extractor := openid4vp.NewClaimsExtractor()

	byID := make(map[string]ResolvedCredentialQuery, len(opSession.DCQL.Credentials))
	for _, c := range opSession.DCQL.Credentials {
		byID[c.ID] = c
	}
	entries := make(map[string][]CredentialEntry, len(resp.VPToken))
	satisfied := make(map[string]bool, len(resp.VPToken))
	for credID, tokens := range resp.VPToken {
		resolvedQuery, ok := byID[credID]
		if !ok {
			return nil, fmt.Errorf("%w: wallet returned unknown credential id %q", ErrOPAccessDenied, credID)
		}
		queryEntries, ok, err := o.resolveQueryEntries(ctx, extractor, resolvedQuery, tokens)
		if err != nil {
			return nil, err
		}
		if ok && len(queryEntries) > 0 {
			entries[credID] = queryEntries
			satisfied[credID] = true
		}
	}

	satisfiedSets, err := evaluateCredentialSets(opSession.DCQL, satisfied)
	if err != nil {
		return nil, err
	}
	return &OPPresentationResult{
		Entries:                 entries,
		SatisfiedSets:           satisfiedSets,
		CredentialSetsRequested: len(opSession.DCQL.CredentialSets) > 0,
		sessionID:               opSession.ID,
	}, nil
}

// resolveQueryEntries validates every token presented for one credential
// query. It returns (entries, true, nil) when all tokens satisfy the
// query's type, value, and claim_sets constraints; (nil, false, nil)
// when a constraint is unmet (the query is unsatisfied but the overall
// response may still succeed); and an error only for a malformed token.
func (o *OP) resolveQueryEntries(ctx context.Context, extractor *openid4vp.ClaimsExtractor, resolvedQuery ResolvedCredentialQuery, tokens []string) ([]CredentialEntry, bool, error) {
	var queryEntries []CredentialEntry
	for _, token := range tokens {
		claims, err := extractor.ExtractClaimsFromVPToken(ctx, token)
		if err != nil {
			return nil, false, fmt.Errorf("%w: extract claims: %v", ErrOPAccessDenied, err)
		}
		if err := resolvedQuery.verifyCredentialType(claims); err != nil {
			return nil, false, nil
		}
		if err := resolvedQuery.postValidateValues(claims); err != nil {
			return nil, false, nil
		}
		matchedOption, err := resolvedQuery.selectClaimSetOption(claims)
		if err != nil {
			return nil, false, nil
		}
		filtered := resolvedQuery.filterClaims(claims, matchedOption)
		queryEntries = append(queryEntries, CredentialEntry{
			Type:   append([]string(nil), resolvedQuery.Type...),
			Claims: filtered,
			Verification: &Verification{
				TrustStatus: TrustStatusNotChecked,
			},
			// Preserve the unfiltered claims internally so subject
			// derivation can still read the stable identifier even when the
			// RP did not request it to be disclosed. verified_at is omitted
			// because this layer performs no cryptographic verification.
			subjectSource: claims,
		})
	}
	return queryEntries, true, nil
}

// evaluateCredentialSets implements the §4.1.2 requirement rules: when
// credential_sets is absent every credential query is required; when it
// is present, each required set must have one fully-satisfied option,
// while optional sets simply drop out when unsatisfied.
func evaluateCredentialSets(dcql ResolvedDCQL, satisfied map[string]bool) ([]ResolvedCredentialSet, error) {
	if len(dcql.CredentialSets) == 0 {
		for _, q := range dcql.Credentials {
			if !satisfied[q.ID] {
				return nil, fmt.Errorf("%w: required credential %q was not satisfied", ErrOPAccessDenied, q.ID)
			}
		}
		return nil, nil
	}
	var out []ResolvedCredentialSet
	for _, set := range dcql.CredentialSets {
		optionSatisfied := false
		for _, option := range set.Options {
			all := true
			for _, id := range option {
				if !satisfied[id] {
					all = false
					break
				}
			}
			if all {
				optionSatisfied = true
				break
			}
		}
		if optionSatisfied {
			out = append(out, set)
			continue
		}
		if set.Required {
			return nil, fmt.Errorf("%w: required credential set %q was not satisfied", ErrOPAccessDenied, set.ID)
		}
	}
	return out, nil
}

// verifyCredentialType confirms the presented credential's format-specific
// type (vct for SD-JWT VC, type array for W3C) matches one of the types
// the RP requested, so a credential of a different type cannot be
// mislabelled as the requested one (§5.1.2).
func (r ResolvedCredentialQuery) verifyCredentialType(claims map[string]any) error {
	if len(r.Type) == 0 {
		return nil
	}
	switch r.Format {
	case openid4vp.FormatSDJWTVC:
		vct, _ := claims["vct"].(string)
		if !containsString(r.Type, vct) {
			return fmt.Errorf("%w: presented vct %q does not match requested type", ErrOPAccessDenied, vct)
		}
	case openid4vp.FormatMsoMdoc:
		// The pinned extractor auto-detects the token format and flattens
		// mdoc namespaces without exposing the credential's docType, so the
		// requested docType cannot be verified and an SD-JWT could be
		// submitted under an mdoc id and mislabelled. Reject mdoc
		// presentations until the extractor exposes the docType.
		return fmt.Errorf("%w: mso_mdoc docType cannot be verified by the pinned extractor", ErrOPAccessDenied)
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		// A W3C type_values inner array is an AND constraint: the
		// credential must carry every requested type. A missing or
		// non-array "type" claim is malformed and cannot satisfy it.
		types, ok := claims["type"].([]any)
		if !ok {
			return fmt.Errorf("%w: presented credential has a missing or malformed type claim", ErrOPAccessDenied)
		}
		present := make(map[string]struct{}, len(types))
		for _, got := range types {
			if s, ok := got.(string); ok {
				present[s] = struct{}{}
			}
		}
		for _, want := range r.Type {
			if _, ok := present[want]; !ok {
				return fmt.Errorf("%w: presented type is missing required value %q", ErrOPAccessDenied, want)
			}
		}
	}
	return nil
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
