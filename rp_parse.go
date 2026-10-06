package credbridge

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// idTokenClockSkewSeconds is the leeway allowed when validating ID Token
// exp/iat against the local clock (RFC §7.1, OIDC Core §3.1.3.7).
const idTokenClockSkewSeconds int64 = 120

// RPClaims is the decoded ID Token / UserInfo payload with the bridge
// claim exposed as a typed slice.
type RPClaims struct {
	Issuer                  string
	Subject                 string
	Audience                string
	Audiences               []string
	IssuedAt                int64
	ExpiresAt               int64
	Nonce                   string
	PresentedCredentialSets PresentedCredentialSets

	// Raw exposes the full ID Token / UserInfo map for callers that
	// need claims not modelled by RPClaims.
	Raw map[string]any
}

// ParseIDToken decodes idToken without verifying its signature. Use it
// only when the surrounding transport already guarantees authenticity —
// for example when the ID Token was fetched through TLS from the token
// endpoint with client authentication. For production deployments,
// verify the signature against the JWKS obtained through Discover
// separately (this package exposes RPClaims.Raw so callers can drive
// their preferred verifier).
//
// Standard claim checks that ParseIDToken performs regardless:
//   - iss must equal RPConfig.IssuerURL.
//   - aud must contain RPConfig.ClientID.
//   - sub must be a non-empty string.
//   - azp, when present, must be a non-empty string equal to RPConfig.ClientID.
//   - nonce must equal expectedNonce (required and compared).
//   - iat and exp must be present, and exp must be in the future.
func (r *RP) ParseIDToken(_ context.Context, idToken, expectedNonce string) (*RPClaims, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(idToken, claims); err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrRPIDTokenInvalid, err)
	}
	return r.parseClaimsMap(claims, expectedNonce, true)
}

// FetchUserInfoClaims decodes a raw UserInfo JSON payload. It performs
// no HTTP call — the caller is responsible for issuing the request with
// the appropriate access token.
//
// expectedSubject binds the UserInfo response to the ID Token: pass the
// ID Token's sub so a response minted for a different subject is
// rejected (OIDC Core §5.3.2). It is required.
func (r *RP) FetchUserInfoClaims(body []byte, expectedSubject string) (*RPClaims, error) {
	raw := map[string]any{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrRPIDTokenInvalid, err)
	}
	rc, err := r.parseClaimsMap(raw, "", false)
	if err != nil {
		return nil, err
	}
	if expectedSubject == "" {
		return nil, fmt.Errorf("%w: expected subject is required to bind UserInfo to the ID Token", ErrRPIDTokenInvalid)
	}
	if rc.Subject != expectedSubject {
		return nil, fmt.Errorf("%w: sub mismatch: UserInfo subject %q is not the ID Token subject", ErrRPIDTokenInvalid, rc.Subject)
	}
	return rc, nil
}

// parseClaimsMap extracts the standard claims and, when present, the
// §5.1 "presented_credential_sets" array. checkStandard toggles the
// iss / aud / iat / exp / nonce validation required for ID Tokens.
func (r *RP) parseClaimsMap(claims map[string]any, expectedNonce string, checkStandard bool) (*RPClaims, error) {
	rc := &RPClaims{Raw: claims}
	if v, ok := claims["iss"].(string); ok {
		rc.Issuer = v
	}
	if v, ok := claims["sub"].(string); ok {
		rc.Subject = v
	}
	rc.Audiences = extractAudiences(claims["aud"])
	if len(rc.Audiences) > 0 {
		rc.Audience = rc.Audiences[0]
	}
	rc.IssuedAt = extractInt64(claims["iat"])
	rc.ExpiresAt = extractInt64(claims["exp"])
	if v, ok := claims["nonce"].(string); ok {
		rc.Nonce = v
	}
	if checkStandard {
		if rc.Issuer != r.cfg.IssuerURL {
			return nil, fmt.Errorf("%w: iss mismatch: got %q", ErrRPIDTokenInvalid, rc.Issuer)
		}
		if !containsString(rc.Audiences, r.cfg.ClientID) {
			return nil, fmt.Errorf("%w: aud mismatch: got %v", ErrRPIDTokenInvalid, rc.Audiences)
		}
		// An ID Token MUST carry a non-empty string sub (OIDC Core §2);
		// a missing or wrongly-typed subject leaves rc.Subject empty.
		if rc.Subject == "" {
			return nil, fmt.Errorf("%w: sub is missing or not a string", ErrRPIDTokenInvalid)
		}
		// azp (authorized party), when present, must be a non-empty string
		// equal to this client even if the client is merely one of several
		// audiences (OIDC Core §2). A non-string or empty value is rejected
		// so an attacker cannot evade the check by changing the JSON type.
		if azpRaw, present := claims["azp"]; present {
			azp, ok := azpRaw.(string)
			if !ok || azp == "" || azp != r.cfg.ClientID {
				return nil, fmt.Errorf("%w: azp is missing, malformed, or does not match the client", ErrRPIDTokenInvalid)
			}
		}
		if rc.IssuedAt == 0 || rc.ExpiresAt == 0 {
			return nil, fmt.Errorf("%w: iat or exp missing", ErrRPIDTokenInvalid)
		}
		now := r.now().Unix()
		if rc.ExpiresAt <= now-idTokenClockSkewSeconds {
			return nil, fmt.Errorf("%w: token expired", ErrRPIDTokenInvalid)
		}
		if rc.IssuedAt > now+idTokenClockSkewSeconds {
			return nil, fmt.Errorf("%w: iat is too far in the future", ErrRPIDTokenInvalid)
		}
		if expectedNonce == "" {
			return nil, fmt.Errorf("%w: expected nonce is required for ID Token validation", ErrRPIDTokenInvalid)
		}
		if rc.Nonce != expectedNonce {
			return nil, fmt.Errorf("%w: nonce mismatch", ErrRPIDTokenInvalid)
		}
	}
	setsAny, ok := claims[PresentedCredentialSetsClaim]
	if !ok {
		return rc, nil
	}
	sets, err := decodePresentedCredentialSets(setsAny)
	if err != nil {
		return nil, err
	}
	rc.PresentedCredentialSets = sets
	return rc, nil
}

// extractAudiences returns the JWT "aud" value as a slice of strings,
// coping with both the string and array forms permitted by RFC 7519 and
// preserving every entry so membership (and azp) checks are possible.
func extractAudiences(v any) []string {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil
		}
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// containsString reports whether target is present in list.
func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

// extractInt64 converts a JWT NumericDate value to int64 regardless of
// whether encoding/json decoded it as float64 or json.Number.
func extractInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0
		}
		return i
	}
	return 0
}

// decodePresentedCredentialSets decodes the §5.1.1 top-level JSON
// array into a typed PresentedCredentialSets, or returns
// [ErrRPUnexpectedResponseShape] if v is not an array.
func decodePresentedCredentialSets(v any) (PresentedCredentialSets, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, ErrRPUnexpectedResponseShape
	}
	sets := make(PresentedCredentialSets, 0, len(arr))
	for i, elem := range arr {
		b, err := json.Marshal(elem)
		if err != nil {
			return nil, fmt.Errorf("credbridge/rp: element %d: %w", i, err)
		}
		var s PresentedCredentialSet
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("credbridge/rp: element %d: %w", i, err)
		}
		sets = append(sets, s)
	}
	return sets, nil
}
