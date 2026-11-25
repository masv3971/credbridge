package credbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

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
		cq.Meta.TypeValues = cloneOptions(r.TypeValues)
		if len(cq.Meta.TypeValues) == 0 {
			cq.Meta.TypeValues = [][]string{append([]string(nil), r.Type...)}
		}
	}
	// DCQL defaults multiple to false, so only an explicit true is sent.
	if r.Multiple {
		multiple := true
		cq.Multiple = &multiple
	}
	for _, cl := range r.Claims {
		cq.Claims = append(cq.Claims, openid4vp.ClaimQuery{
			ID:     cl.ID,
			Path:   openid4vp.StringPath(cl.Path...),
			Values: append([]any(nil), cl.Values...),
		})
	}
	cq.ClaimSet = cloneOptions(r.ClaimSets)
	r.addSubjectClaim(&cq)
	// Forward the RP's effective constraints unchanged: without these the
	// wallet would never see trusted_authorities and an explicit
	// require_cryptographic_holder_binding:false would silently revert to
	// the OpenID4VP default of true.
	cq.TrustedAuthorities = append([]openid4vp.TrustedAuthority(nil), r.TrustedAuthorities...)
	holderBinding := r.RequireCryptographicHolderBinding
	cq.RequireCryptographicHolderBinding = &holderBinding
	return cq
}

// addSubjectClaim asks the wallet for the subject claim next to the RP's
// claims, and adds it to every claim_sets option, so a selectively
// disclosing wallet still reveals the identifier sub derivation needs.
// Response filtering uses the RP's own claims, so it is not relayed.
func (r ResolvedCredentialQuery) addSubjectClaim(cq *openid4vp.CredentialQuery) {
	// Without requested claims the wallet may disclose everything anyway.
	if len(r.SubjectClaim) == 0 || len(cq.Claims) == 0 {
		return
	}
	if len(cq.ClaimSet) == 0 {
		for _, cl := range r.Claims {
			if slices.Equal(cl.Path, r.SubjectClaim) {
				return
			}
		}
		cq.Claims = append(cq.Claims, openid4vp.ClaimQuery{Path: openid4vp.StringPath(r.SubjectClaim...)})
		return
	}
	id := "bridge_subject"
	for slices.ContainsFunc(cq.Claims, func(c openid4vp.ClaimQuery) bool { return c.ID == id }) {
		id += "_"
	}
	cq.Claims = append(cq.Claims, openid4vp.ClaimQuery{ID: id, Path: openid4vp.StringPath(r.SubjectClaim...)})
	for i := range cq.ClaimSet {
		cq.ClaimSet[i] = append(cq.ClaimSet[i], id)
	}
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
	if len(tokens) > 1 && !resolvedQuery.Multiple {
		return nil, false, nil
	}
	var queryEntries []CredentialEntry
	for _, token := range tokens {
		claims, err := extractor.ExtractClaimsFromVPToken(ctx, token)
		if err != nil {
			return nil, false, fmt.Errorf("%w: extract claims: %v", ErrOPAccessDenied, err)
		}
		// The extractor returns the whole JWT payload for jwt_vc_json; match
		// and relay only the credential subject, never JWT envelope claims.
		if resolvedQuery.Format == openid4vp.FormatJwtVCJson {
			subject, ok := jwtVCSubject(claims)
			if !ok {
				return nil, false, nil
			}
			claims = subject
		}
		presentedTypes, err := resolvedQuery.verifyCredentialType(claims, token)
		if err != nil {
			return nil, false, nil
		}
		matchedOption, err := resolvedQuery.selectClaimSetOption(claims)
		if err != nil {
			return nil, false, nil
		}
		filtered := resolvedQuery.filterClaims(claims, matchedOption)
		queryEntries = append(queryEntries, CredentialEntry{
			Type:   resolvedQuery.entryType(presentedTypes),
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
	for i, set := range dcql.CredentialSets {
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
			return nil, fmt.Errorf("%w: required credential_sets entry %d was not satisfied", ErrOPAccessDenied, i)
		}
	}
	return out, nil
}

// verifyCredentialType confirms the presented credential's format-specific
// type (vct for SD-JWT VC, type array for W3C) matches one of the types
// the RP requested, so a credential of a different type cannot be
// mislabelled as the requested one (§5.1.2). For W3C formats it returns
// the presented credential's type array, read from token because the
// extractor yields only credentialSubject claims.
func (r ResolvedCredentialQuery) verifyCredentialType(claims map[string]any, token string) ([]string, error) {
	if len(r.Type) == 0 {
		return nil, nil
	}
	switch r.Format {
	case openid4vp.FormatSDJWTVC:
		vct, _ := claims["vct"].(string)
		if !containsString(r.Type, vct) {
			return nil, fmt.Errorf("%w: presented vct %q does not match requested type", ErrOPAccessDenied, vct)
		}
	case openid4vp.FormatMsoMdoc:
		// The pinned extractor auto-detects the token format and flattens
		// mdoc namespaces without exposing the credential's docType, so the
		// requested docType cannot be verified and an SD-JWT could be
		// submitted under an mdoc id and mislabelled. Reject mdoc
		// presentations until the extractor exposes the docType.
		return nil, fmt.Errorf("%w: mso_mdoc docType cannot be verified by the pinned extractor", ErrOPAccessDenied)
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		// Each type_values alternative is an AND constraint; the credential
		// satisfies the query when it carries every type of any one of them.
		presented, ok := w3cTypes(token)
		if !ok {
			return nil, fmt.Errorf("%w: presented credential has a missing or malformed type", ErrOPAccessDenied)
		}
		alternatives := r.TypeValues
		if len(alternatives) == 0 {
			alternatives = [][]string{r.Type}
		}
		for _, alt := range alternatives {
			if containsAll(presented, alt) {
				return presented, nil
			}
		}
		return nil, fmt.Errorf("%w: presented type satisfies no requested type_values alternative", ErrOPAccessDenied)
	}
	return nil, nil
}

// containsAll reports whether every element of want is present in have.
func containsAll(have, want []string) bool {
	for _, w := range want {
		if !containsString(have, w) {
			return false
		}
	}
	return true
}

// w3cTypes returns the credential type array of a W3C token: a JWT
// (jwt_vc_json, type under "vc" or at the top level), a credential
// document, or a presentation embedding exactly one credential.
func w3cTypes(token string) ([]string, bool) {
	trimmed := strings.TrimSpace(token)
	if strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			return nil, false
		}
		return w3cDocumentTypes(doc)
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) < 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, false
	}
	cred, ok := jwtVCCredential(body)
	if !ok {
		return nil, false
	}
	return typeList(cred["type"])
}

// jwtVCCredential returns the credential object of a JWT payload: the "vc"
// claim (JWT VC data model 1.1) or, when the payload carries
// credentialSubject itself, the payload (VC data model 2.0 secured as JWT).
func jwtVCCredential(payload map[string]any) (map[string]any, bool) {
	if vc, ok := payload["vc"].(map[string]any); ok {
		return vc, true
	}
	if _, ok := payload["credentialSubject"]; ok {
		return payload, true
	}
	return nil, false
}

// jwtVCSubject returns the credentialSubject claims of a JWT VC payload.
func jwtVCSubject(payload map[string]any) (map[string]any, bool) {
	cred, ok := jwtVCCredential(payload)
	if !ok {
		return nil, false
	}
	subject, ok := cred["credentialSubject"].(map[string]any)
	return subject, ok
}

func w3cDocumentTypes(doc map[string]any) ([]string, bool) {
	embedded, ok := doc["verifiableCredential"]
	if !ok {
		return typeList(doc["type"])
	}
	// Several embedded credentials would need per-credential type
	// attribution that the merged subject claims cannot provide.
	list, ok := embedded.([]any)
	if !ok {
		list = []any{embedded}
	}
	if len(list) != 1 {
		return nil, false
	}
	switch e := list[0].(type) {
	case string:
		return w3cTypes(e)
	case map[string]any:
		return w3cDocumentTypes(e)
	}
	return nil, false
}

// typeList converts a JSON "type" member (string or string array) to a
// non-empty []string.
func typeList(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, t != ""
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, len(out) > 0
	}
	return nil, false
}

// entryType returns the Credential Entry "type" array. W3C credentials
// keep their full presented type array (§5.1.2), which may be a superset
// of the requested types; other formats use the requested type.
func (r ResolvedCredentialQuery) entryType(presented []string) []string {
	if len(presented) > 0 {
		return append([]string(nil), presented...)
	}
	return append([]string(nil), r.Type...)
}

// claimSatisfied reports whether cl is disclosed in claims and, when the
// RP constrained "values" (Appendix A.4), matches one of them.
func claimSatisfied(cl ResolvedClaim, claims map[string]any) bool {
	got, ok := lookupClaim(claims, cl.Path)
	if !ok {
		return false
	}
	if len(cl.Values) == 0 {
		return true
	}
	for _, want := range cl.Values {
		if MatchValue(got, want) {
			return true
		}
	}
	return false
}

// selectClaimSetOption implements §4.1.2's deterministic "first
// satisfied option" selection: iterate ClaimSets in RP-supplied order
// and return the first option whose claims are all disclosed and match
// their "values" constraints. Without ClaimSets every requested claim
// must be satisfied and the returned option is nil. Returns
// [ErrOPAccessDenied] when the disclosure does not satisfy the query.
func (r ResolvedCredentialQuery) selectClaimSetOption(claims map[string]any) ([]string, error) {
	if len(r.ClaimSets) == 0 {
		for _, cl := range r.Claims {
			if !claimSatisfied(cl, claims) {
				return nil, fmt.Errorf("%w: requested claim %v is missing or not in requested values", ErrOPAccessDenied, cl.Path)
			}
		}
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
			if !exists || !claimSatisfied(cl, claims) {
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
