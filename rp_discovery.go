package credbridge

import (
	"context"
	"encoding/json"
	"errors"
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

// maxDiscoveryBodyBytes caps the discovery document size the RP will read
// into memory (1 MiB), guarding against an oversized or malicious body.
const maxDiscoveryBodyBytes int64 = 1 << 20

type discoveryCache struct {
	mu       sync.Mutex
	value    *RPDiscoveryMetadata
	expires  time.Time
	inflight *discoveryCall
}

// discoveryCall is one in-flight discovery fetch shared by concurrent
// callers.
type discoveryCall struct {
	done chan struct{}
	md   *RPDiscoveryMetadata
	err  error
}

// Discover fetches /.well-known/openid-configuration from the OP, decodes
// it, and caches the result for RPConfig.DiscoveryCacheTTL. Concurrent
// callers share one fetch and each honours its own context while waiting.
func (r *RP) Discover(ctx context.Context) (*RPDiscoveryMetadata, error) {
	for {
		r.cache.mu.Lock()
		if r.cache.value != nil && r.now().Before(r.cache.expires) {
			md := r.cache.value
			r.cache.mu.Unlock()
			return md, nil
		}
		if call := r.cache.inflight; call != nil {
			r.cache.mu.Unlock()
			select {
			case <-call.done:
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %v", ErrRPDiscoveryUnreachable, ctx.Err())
			}
			// A fetch aborted by another caller's context must not fail
			// callers whose contexts are still live; fetch again instead.
			if call.err != nil && ctx.Err() == nil &&
				(errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) {
				continue
			}
			return call.md, call.err
		}
		call := &discoveryCall{done: make(chan struct{})}
		r.cache.inflight = call
		r.cache.mu.Unlock()

		md, err := r.fetchDiscovery(ctx)

		r.cache.mu.Lock()
		if err == nil {
			r.cache.value = md
			r.cache.expires = r.now().Add(r.cfg.DiscoveryCacheTTL)
		}
		r.cache.inflight = nil
		call.md, call.err = md, err
		r.cache.mu.Unlock()
		close(call.done)
		return md, err
	}
}

// fetchDiscovery performs the HTTP discovery request and validates the
// returned document.
func (r *RP) fetchDiscovery(ctx context.Context) (*RPDiscoveryMetadata, error) {
	wellKnown, err := wellKnownConfigURL(r.cfg.IssuerURL, r.cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPDiscoveryUnreachable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRPDiscoveryUnreachable, err)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRPDiscoveryUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %s", ErrRPDiscoveryUnreachable, resp.Status)
	}
	// Bound the response so a configured or compromised OP cannot exhaust
	// RP memory by streaming an arbitrarily large body. Read one byte past
	// the cap to detect overflow.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrRPDiscoveryUnreachable, err)
	}
	if int64(len(body)) > maxDiscoveryBodyBytes {
		return nil, fmt.Errorf("%w: discovery document exceeds %d bytes", ErrRPDiscoveryUnreachable, maxDiscoveryBodyBytes)
	}
	md := &RPDiscoveryMetadata{}
	if err := json.Unmarshal(body, md); err != nil {
		return nil, fmt.Errorf("%w: parse body: %v", ErrRPDiscoveryUnreachable, err)
	}
	if md.Issuer != r.cfg.IssuerURL {
		return nil, fmt.Errorf("%w: issuer mismatch: got %q want %q", ErrRPDiscoveryUnreachable, md.Issuer, r.cfg.IssuerURL)
	}
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

// wellKnownConfigURL applies the OIDC Discovery §4 rule: the suffix
// /.well-known/openid-configuration is appended to the issuer path, so
// https://op.example/tenant maps to
// https://op.example/tenant/.well-known/openid-configuration. Only
// https issuers are accepted unless allowInsecure is set.
func wellKnownConfigURL(issuer string, allowInsecure bool) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("invalid issuer %q: %w", issuer, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	if u.Scheme != "https" && !(allowInsecure && u.Scheme == "http") {
		return "", fmt.Errorf("issuer %q must use https", issuer)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/.well-known/openid-configuration"
	u.RawPath = ""
	return u.String(), nil
}
