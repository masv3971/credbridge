package credbridge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// OPAuthorizationRequest is the parsed OIDC authorization request the
// Relying Party sent to the OP.
type OPAuthorizationRequest struct {
	ClientID     string
	RedirectURI  string
	State        string
	Nonce        string
	Scopes       []string
	ResponseType string

	// DCQLQuery is populated when the request contained a "dcql_query"
	// member inside the OIDC "claims" parameter (Section 4.1.2).
	DCQLQuery *openid4vp.DCQL

	// CredentialSetIDs carries the OPTIONAL Credential Set "id" values
	// that RFC §5.1.1 layers on top of OpenID4VP's Credential Set Query.
	// Slot i corresponds to DCQLQuery.CredentialSets[i];
	// leave a slot empty to omit the id for that entry. Extra slots past
	// len(DCQLQuery.CredentialSets) are ignored.
	CredentialSetIDs []string
}

// StartAuthorization validates req against the RFC and initialises a
// session. The returned session is stored in the OP's OPStorage and
// can be handed to BuildWalletRequest.
func (o *OP) StartAuthorization(ctx context.Context, req OPAuthorizationRequest) (*OPSession, error) {
	if req.ClientID == "" {
		return nil, fmt.Errorf("%w: missing client_id", ErrOPInvalidRequest)
	}
	if req.RedirectURI == "" {
		return nil, fmt.Errorf("%w: missing redirect_uri", ErrOPInvalidRequest)
	}
	if req.ResponseType != "" && req.ResponseType != "code" {
		return nil, fmt.Errorf("%w: response_type must be \"code\"", ErrOPInvalidRequest)
	}
	credScopes := req.credentialScopes()
	if len(credScopes) == 0 {
		return nil, fmt.Errorf("%w: no credential scope in request", ErrOPInvalidRequest)
	}

	// §5.3 step 1: ignore scopes not in credential_presentations_supported.
	supported := make([]string, 0, len(credScopes))
	for _, s := range credScopes {
		if _, ok := o.cfg.CredentialPresentations[s]; ok {
			supported = append(supported, s)
		}
	}
	if len(supported) == 0 {
		return nil, ErrOPUnsupportedScope
	}

	// §4.1.2: reject dcql_query when the OP does not support the mode.
	if req.DCQLQuery != nil && !o.cfg.DCQLQuerySupported {
		return nil, fmt.Errorf("%w: OP does not support dcql_query", ErrOPInvalidRequest)
	}
	if req.DCQLQuery != nil {
		if err := o.validateRPQueryProfile(req.DCQLQuery, supported); err != nil {
			return nil, err
		}
	}

	resolvedDCQL, err := o.buildResolvedDCQL(supported, req.DCQLQuery, req.CredentialSetIDs)
	if err != nil {
		return nil, err
	}

	nonce := req.Nonce
	if nonce == "" {
		generated, err := randomToken()
		if err != nil {
			return nil, err
		}
		nonce = generated
	}

	sessionID, err := randomToken()
	if err != nil {
		return nil, err
	}
	opSession := &OPSession{
		ID:                  sessionID,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               nonce,
		RequestedScopes:     supported,
		DCQL:                resolvedDCQL,
		RPDCQLQuerySupplied: req.DCQLQuery != nil,
		CreatedAt:           o.now().Unix(),
	}
	if err := o.storage.Put(ctx, opSession); err != nil {
		return nil, fmt.Errorf("credbridge/op: persist session: %w", err)
	}
	return opSession, nil
}

// credentialScopes returns req.Scopes with "openid" and empty entries
// stripped, leaving only the credential type scopes per §4.1.
func (req OPAuthorizationRequest) credentialScopes() []string {
	out := make([]string, 0, len(req.Scopes))
	for _, s := range req.Scopes {
		s = strings.TrimSpace(s)
		if s == "" || s == "openid" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// validateRPQueryProfile enforces the Section 4.1.2 profile rules and
// the reserved-prefix rule from Appendix A.2.
func (o *OP) validateRPQueryProfile(q *openid4vp.DCQL, scopes []string) error {
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = struct{}{}
	}
	// Build reverse index: format+type → scope for coverage check.
	typeToScope := make(map[string]string, len(o.cfg.CredentialPresentations))
	for scope, cfg := range o.cfg.CredentialPresentations {
		typeToScope[typeKey(cfg.Format, cfg.Type)] = scope
	}
	seenQueryIDs := make(map[string]struct{}, len(q.Credentials))
	for _, cq := range q.Credentials {
		if !isValidDCQLID(cq.ID) {
			return fmt.Errorf("%w: credential query id %q violates OpenID4VP \u00a76.1 charset", ErrOPInvalidRequest, cq.ID)
		}
		if _, dup := seenQueryIDs[cq.ID]; dup {
			return fmt.Errorf("%w: duplicate credential query id %q", ErrOPInvalidRequest, cq.ID)
		}
		seenQueryIDs[cq.ID] = struct{}{}
		if strings.HasPrefix(cq.ID, BridgeIDPrefix) {
			return fmt.Errorf("%w: %q", ErrOPBridgePrefixReserved, cq.ID)
		}
		for _, cl := range cq.Claims {
			if cl.ID != "" && !isValidDCQLID(cl.ID) {
				return fmt.Errorf("%w: claim query id %q violates OpenID4VP \u00a76.1 charset", ErrOPInvalidRequest, cl.ID)
			}
		}
		if len(cq.ClaimSet) > 0 {
			ids := make(map[string]struct{}, len(cq.Claims))
			for _, cl := range cq.Claims {
				if cl.ID == "" {
					return fmt.Errorf("%w: claim_sets present but a claim is missing the required id", ErrOPInvalidRequest)
				}
				if _, dup := ids[cl.ID]; dup {
					return fmt.Errorf("%w: duplicate claim id %q", ErrOPInvalidRequest, cl.ID)
				}
				ids[cl.ID] = struct{}{}
			}
			for _, option := range cq.ClaimSet {
				for _, ref := range option {
					if _, ok := ids[ref]; !ok {
						return fmt.Errorf("%w: claim_sets references unknown claim id %q", ErrOPInvalidRequest, ref)
					}
				}
			}
		}
		key, err := metaTypeKey(cq)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrOPInvalidRequest, err)
		}
		scope, ok := typeToScope[key]
		if !ok {
			return fmt.Errorf("%w: credential query %q targets an unsupported type", ErrOPInvalidRequest, cq.ID)
		}
		if _, requested := scopeSet[scope]; !requested {
			return fmt.Errorf("%w: credential query %q refers to scope %q which is not in the authorization request", ErrOPInvalidRequest, cq.ID, scope)
		}
	}
	return nil
}

// typeKey builds the format|type string used to index the OP's
// credential_presentations_supported mapping (§5.2).
func typeKey(format string, types []string) string {
	return format + "|" + strings.Join(types, ",")
}

// metaTypeKey extracts the format-specific type identifier from cq's
// "meta" object and returns a typeKey suitable for lookup (§5.2).
func metaTypeKey(cq openid4vp.CredentialQuery) (string, error) {
	switch cq.Format {
	case openid4vp.FormatSDJWTVC:
		if len(cq.Meta.VCTValues) == 0 {
			return "", errors.New("dc+sd-jwt credential query missing vct_values")
		}
		return typeKey(cq.Format, cq.Meta.VCTValues), nil
	case openid4vp.FormatMsoMdoc:
		if cq.Meta.DoctypeValue == "" {
			return "", errors.New("mso_mdoc credential query missing doctype_value")
		}
		return typeKey(cq.Format, []string{cq.Meta.DoctypeValue}), nil
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		if len(cq.Meta.TypeValues) == 0 || len(cq.Meta.TypeValues[0]) == 0 {
			return "", errors.New("w3c credential query missing type_values")
		}
		return typeKey(cq.Format, cq.Meta.TypeValues[0]), nil
	default:
		return "", fmt.Errorf("unsupported credential format %q", cq.Format)
	}
}

// randomToken returns a base64url-encoded random 24-byte string used
// as an OP-generated OIDC nonce fallback (§7.1) and OPSession id. It
// returns an error when the system CSPRNG fails, so callers abort rather
// than fall back to a predictable value that would collide session ids
// and defeat nonce replay protection.
func randomToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("credbridge/op: read entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
