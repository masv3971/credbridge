package credbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// RPAuthorizationRequestOptions carries the RP's choices for one OIDC
// authorization request.
type RPAuthorizationRequestOptions struct {
	// Scopes lists credential type scopes (Section 4.1). The "openid"
	// scope is always added automatically.
	Scopes []string
	// State is the OAuth state parameter.
	State string
	// Nonce is required (RFC §7.1 binds it to the wallet presentation).
	Nonce string
	// DCQLQuery, when non-nil, activates the DCQL-based mode
	// (Section 4.1.2). BuildAuthorizationURL will return
	// ErrRPDCQLNotSupported if the OP's discovery document reports
	// dcql_query_supported=false.
	DCQLQuery *openid4vp.DCQL
	// CredentialSetIDs carries the OPTIONAL Credential Set "id" values
	// that RFC §5.1.1 layers on top of OpenID4VP DCQL.
	// Slot i aligns with DCQLQuery.CredentialSets[i]; leave empty to
	// omit the id for that entry.
	CredentialSetIDs []string
	// ResponseType defaults to "code".
	ResponseType string
	// ExtraParams are appended to the URL verbatim.
	ExtraParams url.Values
}

// BuildAuthorizationURL constructs the OIDC authorization URL for the OP.
// It refuses to include a dcql_query when the OP does not advertise
// support for it (Section 4.1.2 last paragraph).
func (r *RP) BuildAuthorizationURL(ctx context.Context, opts RPAuthorizationRequestOptions) (string, error) {
	md, err := r.Discover(ctx)
	if err != nil {
		return "", err
	}
	if err := oauth2.ValidateRedirectURIScheme(r.cfg.RedirectURI); err != nil {
		return "", fmt.Errorf("credbridge/rp: %w", err)
	}
	if opts.Nonce == "" {
		return "", errors.New("credbridge/rp: nonce is required (RFC §7.1)")
	}
	if opts.DCQLQuery != nil && !md.DCQLQuerySupported {
		return "", ErrRPDCQLNotSupported
	}
	scopes := append([]string{"openid"}, opts.Scopes...)
	responseType := opts.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	q := url.Values{}
	q.Set("response_type", responseType)
	q.Set("client_id", r.cfg.ClientID)
	q.Set("redirect_uri", r.cfg.RedirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("nonce", opts.Nonce)
	if opts.State != "" {
		q.Set("state", opts.State)
	}
	if opts.DCQLQuery != nil {
		dcql, err := marshalDCQLWithSetIDs(opts.DCQLQuery, opts.CredentialSetIDs)
		if err != nil {
			return "", fmt.Errorf("credbridge/rp: encode dcql: %w", err)
		}
		claimsParam := map[string]any{
			"id_token": map[string]any{
				"dcql_query": json.RawMessage(dcql),
			},
		}
		encoded, err := json.Marshal(claimsParam)
		if err != nil {
			return "", fmt.Errorf("credbridge/rp: encode claims: %w", err)
		}
		q.Set("claims", string(encoded))
	}
	for k, vals := range opts.ExtraParams {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	base, err := url.Parse(md.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("credbridge/rp: invalid authorization_endpoint: %w", err)
	}
	if base.RawQuery == "" {
		base.RawQuery = q.Encode()
	} else {
		base.RawQuery = base.RawQuery + "&" + q.Encode()
	}
	return base.String(), nil
}

// marshalDCQLWithSetIDs marshals dcql and injects the RFC §5.1.1
// Credential Set "id" values into each credential_sets entry.
func marshalDCQLWithSetIDs(dcql *openid4vp.DCQL, ids []string) ([]byte, error) {
	b, err := json.Marshal(dcql)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(dcql.CredentialSets) == 0 {
		return b, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	var sets []map[string]any
	if err := json.Unmarshal(obj["credential_sets"], &sets); err != nil {
		return nil, err
	}
	for i := range sets {
		if i >= len(ids) || ids[i] == "" {
			continue
		}
		sets[i]["id"] = ids[i]
	}
	enriched, err := json.Marshal(sets)
	if err != nil {
		return nil, err
	}
	obj["credential_sets"] = enriched
	return json.Marshal(obj)
}
