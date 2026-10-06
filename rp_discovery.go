package credbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RPDiscoveryMetadata mirrors the discovery document returned by an OP
// implementing this draft. It exposes only the members an RP needs to
// interact with the bridge.
type RPDiscoveryMetadata struct {
	Issuer                           string                               `json:"issuer"`
	AuthorizationEndpoint            string                               `json:"authorization_endpoint"`
	TokenEndpoint                    string                               `json:"token_endpoint"`
	UserInfoEndpoint                 string                               `json:"userinfo_endpoint,omitempty"`
	JWKSURI                          string                               `json:"jwks_uri,omitempty"`
	ClaimsSupported                  []string                             `json:"claims_supported,omitempty"`
	ScopesSupported                  []string                             `json:"scopes_supported,omitempty"`
	CredentialPresentationsSupported map[string]OPDiscoveryCredentialType `json:"credential_presentations_supported"`
	DCQLQuerySupported               bool                                 `json:"dcql_query_supported,omitempty"`
}

// SupportsCredentialScope reports whether scope is advertised in the
// discovery document.
func (m *RPDiscoveryMetadata) SupportsCredentialScope(scope string) bool {
	_, ok := m.CredentialPresentationsSupported[scope]
	return ok
}

type discoveryCache struct {
	mu      sync.Mutex
	value   *RPDiscoveryMetadata
	expires time.Time
}

// Discover fetches /.well-known/openid-configuration from the OP, decodes
// it, and caches the result for RPConfig.DiscoveryCacheTTL.
func (r *RP) Discover(ctx context.Context) (*RPDiscoveryMetadata, error) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	if r.cache.value != nil && r.now().Before(r.cache.expires) {
		return r.cache.value, nil
	}
	wellKnown, err := wellKnownConfigURL(r.cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPDiscoveryUnreachable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPDiscoveryUnreachable, err)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPDiscoveryUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %s", ErrRPDiscoveryUnreachable, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrRPDiscoveryUnreachable, err)
	}
	md := &RPDiscoveryMetadata{}
	if err := json.Unmarshal(body, md); err != nil {
		return nil, fmt.Errorf("%w: parse body: %v", ErrRPDiscoveryUnreachable, err)
	}
	if md.Issuer != r.cfg.IssuerURL {
		return nil, fmt.Errorf("%w: issuer mismatch: got %q want %q", ErrRPDiscoveryUnreachable, md.Issuer, r.cfg.IssuerURL)
	}
	r.cache.value = md
	r.cache.expires = r.now().Add(r.cfg.DiscoveryCacheTTL)
	return md, nil
}

// PrimeDiscovery lets tests inject a discovery document instead of
// fetching one over the network.
func (r *RP) PrimeDiscovery(md *RPDiscoveryMetadata) {
	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()
	r.cache.value = md
	r.cache.expires = r.now().Add(r.cfg.DiscoveryCacheTTL)
}

// wellKnownConfigURL applies the OIDC Discovery §4 issuer-to-well-known
// transformation: /.well-known/openid-configuration is inserted between
// the issuer's authority and its path component, so an issuer such as
// https://op.example/tenant maps to
// https://op.example/.well-known/openid-configuration/tenant rather than
// https://op.example/tenant/.well-known/openid-configuration.
func wellKnownConfigURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("invalid issuer %q: %w", issuer, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	path := strings.TrimRight(u.Path, "/")
	u.Path = "/.well-known/openid-configuration" + path
	return u.String(), nil
}
