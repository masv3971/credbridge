package credbridge

import (
	"errors"
	"net/http"
	"time"
)

// RPConfig configures a Relying Party client.
type RPConfig struct {
	// IssuerURL is the OP's issuer identifier ("https://op.example.org").
	IssuerURL string

	// ClientID identifies the RP to the OP.
	ClientID string

	// RedirectURI is the RP's OIDC redirect endpoint.
	RedirectURI string

	// HTTPClient is used for discovery and JWKS fetches. Defaults to
	// http.DefaultClient.
	HTTPClient *http.Client

	// DiscoveryCacheTTL bounds how long a discovery document is
	// considered fresh. Defaults to 5 minutes.
	DiscoveryCacheTTL time.Duration

	// AllowInsecureHTTP permits an http:// IssuerURL and HTTPS-to-HTTP
	// redirects during discovery. Use only for local tests.
	AllowInsecureHTTP bool

	// Now returns the current time (defaults to time.Now).
	Now func() time.Time
}

// RP is a Relying Party client for the bridge.
type RP struct {
	cfg   RPConfig
	http  *http.Client
	now   func() time.Time
	cache discoveryCache
}

// NewRP constructs an RP client implementing the RFC's Relying Party
// role from cfg.
func NewRP(cfg RPConfig) (*RP, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client := http.DefaultClient
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	}
	cfg.HTTPClient = withoutHTTPSDowngrade(client, cfg.AllowInsecureHTTP)
	if cfg.DiscoveryCacheTTL == 0 {
		cfg.DiscoveryCacheTTL = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &RP{cfg: cfg, http: cfg.HTTPClient, now: cfg.Now}, nil
}

// withoutHTTPSDowngrade returns a copy of c that refuses redirects from
// https to http unless allowInsecure is set; the caller's client is not
// modified.
func withoutHTTPSDowngrade(c *http.Client, allowInsecure bool) *http.Client {
	if allowInsecure {
		return c
	}
	copied := *c
	prev := c.CheckRedirect
	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("credbridge/rp: refusing redirect to a non-https URL")
		}
		if prev != nil {
			return prev(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &copied
}

// validate reports the first missing required field on c.
func (c RPConfig) validate() error {
	if c.IssuerURL == "" {
		return errors.New("credbridge/rp: RPConfig.IssuerURL is required")
	}
	if c.ClientID == "" {
		return errors.New("credbridge/rp: RPConfig.ClientID is required")
	}
	if c.RedirectURI == "" {
		return errors.New("credbridge/rp: RPConfig.RedirectURI is required")
	}
	return nil
}
