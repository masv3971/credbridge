package credbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	url := strings.TrimRight(r.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	if md.Issuer != strings.TrimRight(r.cfg.IssuerURL, "/") && md.Issuer != r.cfg.IssuerURL {
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
