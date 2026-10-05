package credbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// RPClaims is the decoded ID Token / UserInfo payload with the bridge
// claim exposed as a typed slice.
type RPClaims struct {
	Issuer                  string
	Subject                 string
	Audience                string
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
//   - aud must equal RPConfig.ClientID.
//   - nonce must equal expectedNonce (may be empty to skip).
//   - iat and exp must be present.
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
func (r *RP) FetchUserInfoClaims(body []byte, expectedNonce string) (*RPClaims, error) {
	raw := map[string]any{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrRPIDTokenInvalid, err)
	}
	return r.parseClaimsMap(raw, expectedNonce, false)
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
	rc.Audience = extractAudience(claims["aud"])
	rc.IssuedAt = extractInt64(claims["iat"])
	rc.ExpiresAt = extractInt64(claims["exp"])
	if v, ok := claims["nonce"].(string); ok {
		rc.Nonce = v
	}
	if checkStandard {
		if strings.TrimRight(rc.Issuer, "/") != strings.TrimRight(r.cfg.IssuerURL, "/") {
			return nil, fmt.Errorf("%w: iss mismatch: got %q", ErrRPIDTokenInvalid, rc.Issuer)
		}
		if rc.Audience != r.cfg.ClientID {
			return nil, fmt.Errorf("%w: aud mismatch: got %q", ErrRPIDTokenInvalid, rc.Audience)
		}
		if rc.IssuedAt == 0 || rc.ExpiresAt == 0 {
			return nil, fmt.Errorf("%w: iat or exp missing", ErrRPIDTokenInvalid)
		}
		if expectedNonce != "" && rc.Nonce != expectedNonce {
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

// extractAudience returns the JWT "aud" value as a single string,
// coping with both the string and array forms permitted by RFC 7519.
func extractAudience(v any) string {
	switch a := v.(type) {
	case string:
		return a
	case []any:
		if len(a) > 0 {
			if s, ok := a[0].(string); ok {
				return s
			}
		}
	}
	return ""
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
