package credbridge

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/jellydator/ttlcache/v3"
)

// BridgeIDPrefix is the reserved prefix the OP prepends to every
// scope-derived DCQL Credential Query id when it augments a
// DCQL-based request (Appendix A.2).
const BridgeIDPrefix = "bridge_"

// OPWalletProtocol identifies which presentation protocol the OP uses
// against the wallet. Only OpenID4VP is implemented.
type OPWalletProtocol string

const (
	OPWalletProtocolOpenID4VP OPWalletProtocol = "openid4vp"
)

// OPSubjectType selects how the OP derives the "sub" claim (Section 5.5,
// OIDC Core §8).
type OPSubjectType string

const (
	// OPSubjectTypePairwise derives a per-client pairwise identifier and
	// requires a deployment-specific PairwiseSalt.
	OPSubjectTypePairwise OPSubjectType = "pairwise"
	// OPSubjectTypePublic returns the raw credential subject value and is
	// advertised as "public" in discovery metadata.
	OPSubjectTypePublic OPSubjectType = "public"
)

// OPConfig is the configuration for an OP bridge.
type OPConfig struct {
	// Issuer is the OP's issuer identifier (an https URL).
	Issuer string

	// AuthorizationEndpoint, TokenEndpoint, UserInfoEndpoint, JWKSURI are
	// published verbatim in discovery metadata. They must be absolute
	// URLs under Issuer.
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string

	// Signer signs ID Tokens, UserInfo JWTs, and any signed OpenID4VP
	// request objects.
	Signer pki.Signer

	// CredentialPresentations maps scope value → credential type
	// configuration. Populates the discovery
	// credential_presentations_supported member (Section 5.2).
	CredentialPresentations map[string]OPCredentialTypeConfig

	// DCQLQuerySupported toggles the discovery dcql_query_supported flag
	// and the DCQL-based request mode (Section 4.1.2).
	DCQLQuerySupported bool

	// PairwiseSalt is used as HMAC key when deriving pairwise "sub"
	// values (Section 5.5 → OIDC Core §8.1). It is REQUIRED when
	// SubjectType is pairwise (the default) and ignored when SubjectType
	// is public.
	PairwiseSalt []byte

	// SubjectType selects the "sub" derivation and the advertised
	// subject_types_supported value (Section 5.5). Defaults to pairwise,
	// which requires a non-empty PairwiseSalt. Set to public to expose
	// the raw subject value and advertise it accordingly.
	SubjectType OPSubjectType

	// TrustedAuthorityAllowlist restricts which URIs/entity IDs the OP
	// will dereference for trust material (Section 7.4). Nil means "allow
	// nothing"; an empty non-nil map means "explicit-empty allowlist" and
	// off-allowlist entries are silently ignored per §7.4.
	TrustedAuthorityAllowlist map[string]bool

	// WalletProtocol selects the presentation protocol. Defaults to
	// OpenID4VP.
	WalletProtocol OPWalletProtocol

	// Storage persists OPSession values between StartAuthorization and
	// IssueIDToken. Leave nil to use the built-in TTL-cached backend
	// (see defaultOPSessionTTL). Provide your own implementation to
	// plug in Redis, a database, or any other backend.
	Storage OPStorage

	// Now returns the current time (defaults to time.Now).
	Now func() time.Time
}

// OPCredentialTypeConfig describes one entry inside
// credential_presentations_supported (Section 5.2).
type OPCredentialTypeConfig struct {
	// Format is the OpenID4VP format identifier ("dc+sd-jwt",
	// "mso_mdoc", "ldp_vc", "jwt_vc_json").
	Format string

	// Type is the credential type identifier(s) (vct for SD-JWT VC,
	// docType for mdoc, W3C type array for LDP).
	Type []string

	// Claims is the pre-registered claim set returned in scope-based
	// mode. Each element is a DCQL claim path.
	Claims [][]string

	// SubjectClaim is the DCQL claim path whose value the OP uses as the
	// stable identifier input when deriving "sub" (Section 5.5).
	SubjectClaim []string
}

// OP is the OpenID Provider bridge.
type OP struct {
	cfg     OPConfig
	vp      *openid4vp.Client
	storage OPStorage
	now     func() time.Time
}

// NewOP constructs an OP bridge implementing the RFC's OpenID Provider
// role from cfg.
func NewOP(ctx context.Context, cfg OPConfig) (*OP, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.WalletProtocol == "" {
		cfg.WalletProtocol = OPWalletProtocolOpenID4VP
	}
	storage := cfg.Storage
	if storage == nil {
		storage = newDefaultOPStorage()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	vp, err := openid4vp.New(ctx, &openid4vp.Config{})
	if err != nil {
		return nil, fmt.Errorf("credbridge/op: init openid4vp client: %w", err)
	}
	return &OP{cfg: cfg, vp: vp, storage: storage, now: cfg.Now}, nil
}

// Close releases resources held by the OP (currently the OpenID4VP
// caches). Safe to call more than once.
func (o *OP) Close() {
	if o.vp != nil {
		o.vp.Close()
	}
	if s, ok := o.storage.(interface{ Stop() }); ok {
		s.Stop()
	}
}

// validate reports the first missing or malformed required field on c.
func (c OPConfig) validate() error {
	if c.Issuer == "" {
		return errors.New("credbridge/op: OPConfig.Issuer is required")
	}
	issuerURL, err := parseHTTPSURL(c.Issuer)
	if err != nil {
		return fmt.Errorf("credbridge/op: OPConfig.Issuer invalid: %w", err)
	}
	if c.AuthorizationEndpoint == "" {
		return errors.New("credbridge/op: OPConfig.AuthorizationEndpoint is required")
	}
	if err := validateEndpointUnderIssuer("AuthorizationEndpoint", c.AuthorizationEndpoint, issuerURL); err != nil {
		return err
	}
	if c.TokenEndpoint == "" {
		return errors.New("credbridge/op: OPConfig.TokenEndpoint is required")
	}
	if err := validateEndpointUnderIssuer("TokenEndpoint", c.TokenEndpoint, issuerURL); err != nil {
		return err
	}
	if err := validateEndpointUnderIssuer("UserInfoEndpoint", c.UserInfoEndpoint, issuerURL); err != nil {
		return err
	}
	if err := validateEndpointUnderIssuer("JWKSURI", c.JWKSURI, issuerURL); err != nil {
		return err
	}
	if c.Signer == nil {
		return errors.New("credbridge/op: OPConfig.Signer is required")
	}
	if c.WalletProtocol != "" && c.WalletProtocol != OPWalletProtocolOpenID4VP {
		return fmt.Errorf("credbridge/op: unsupported WalletProtocol %q (only %q is implemented)", c.WalletProtocol, OPWalletProtocolOpenID4VP)
	}
	switch c.SubjectType {
	case "", OPSubjectTypePairwise:
		if len(c.PairwiseSalt) == 0 {
			return errors.New("credbridge/op: OPConfig.PairwiseSalt is required for pairwise SubjectType; set SubjectType=public to expose raw subjects")
		}
	case OPSubjectTypePublic:
	default:
		return fmt.Errorf("credbridge/op: unsupported SubjectType %q", c.SubjectType)
	}
	if len(c.CredentialPresentations) == 0 {
		return errors.New("credbridge/op: OPConfig.CredentialPresentations must contain at least one entry")
	}
	// Two scopes advertising the same format+type would make the
	// format→scope reverse index used during DCQL resolution ambiguous
	// (a query could validate against one scope and resolve against
	// another). Reject such a configuration rather than resolve it
	// nondeterministically.
	seenTypeKeys := make(map[string]string, len(c.CredentialPresentations))
	for scope, cfg := range c.CredentialPresentations {
		if err := validateCredentialTypeConfig(scope, cfg); err != nil {
			return err
		}
		k := typeKey(cfg.Format, cfg.Type)
		if other, dup := seenTypeKeys[k]; dup {
			return fmt.Errorf("credbridge/op: scopes %q and %q both advertise format %q type %v; each credential type may be advertised by only one scope", other, scope, cfg.Format, cfg.Type)
		}
		seenTypeKeys[k] = scope
	}
	return nil
}

// validateCredentialTypeConfig rejects an unsupported credential Format
// and enforces the format-specific Type cardinality so a configuration
// cannot publish metadata that later produces a query whose type check
// is skipped.
func validateCredentialTypeConfig(scope string, cfg OPCredentialTypeConfig) error {
	switch cfg.Format {
	case openid4vp.FormatSDJWTVC:
		// SD-JWT VC metadata carries exactly one type value, the VCT.
		if len(cfg.Type) != 1 {
			return fmt.Errorf("credbridge/op: scope %q: SD-JWT VC Type must be exactly one vct value", scope)
		}
	case openid4vp.FormatLdpVCDCQL, openid4vp.FormatJwtVCJson:
		if len(cfg.Type) == 0 {
			return fmt.Errorf("credbridge/op: scope %q: Type must list at least one value for format %q", scope, cfg.Format)
		}
	case openid4vp.FormatMsoMdoc:
		// The pinned extractor auto-detects the token format and flattens
		// mdoc namespaces without exposing the docType, so an mso_mdoc
		// presentation can never be verified. Reject the configuration
		// rather than advertise a credential type the OP can never fulfil.
		return fmt.Errorf("credbridge/op: scope %q: mso_mdoc is unsupported until the extractor exposes the docType", scope)
	default:
		return fmt.Errorf("credbridge/op: scope %q: unsupported credential Format %q", scope, cfg.Format)
	}
	return nil
}

// parseHTTPSURL parses raw and requires it to be an absolute https URL
// with a host component.
func parseHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("must be an absolute https URL, got %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("must have a host, got %q", raw)
	}
	return u, nil
}

// validateEndpointUnderIssuer requires a non-empty endpoint to be an
// absolute https URL sharing the issuer's origin (scheme+host), matching
// the configuration contract that published endpoints live under the
// issuer. Empty optional endpoints pass.
func validateEndpointUnderIssuer(name, endpoint string, issuer *url.URL) error {
	if endpoint == "" {
		return nil
	}
	u, err := parseHTTPSURL(endpoint)
	if err != nil {
		return fmt.Errorf("credbridge/op: OPConfig.%s invalid: %w", name, err)
	}
	if u.Scheme != issuer.Scheme || u.Host != issuer.Host {
		return fmt.Errorf("credbridge/op: OPConfig.%s %q is not under issuer origin %q://%s", name, endpoint, issuer.Scheme, issuer.Host)
	}
	return nil
}

// OPStorage persists OPSession state between StartAuthorization and
// IssueIDToken. Implementations MUST be safe for concurrent use. The
// OP invokes these methods internally; callers wire an implementation
// through OPConfig.Storage and never call them directly.
type OPStorage interface {
	Put(ctx context.Context, opSession *OPSession) error
	Get(ctx context.Context, id string) (*OPSession, error)
	Delete(ctx context.Context, id string) error
}

// defaultOPSessionTTL is the retention window the built-in storage
// applies. Chosen to comfortably cover a wallet round-trip plus token
// issuance while still honouring §6.4's "fresh presentation" spirit.
const defaultOPSessionTTL = 10 * time.Minute

// defaultOPStorage is the goroutine-safe TTL-cached OPStorage used
// when the caller does not supply one via OPConfig.Storage.
type defaultOPStorage struct {
	cache *ttlcache.Cache[string, *OPSession]
	ttl   time.Duration
}

func newDefaultOPStorage() OPStorage {
	cache := ttlcache.New[string, *OPSession](
		ttlcache.WithTTL[string, *OPSession](defaultOPSessionTTL),
		ttlcache.WithDisableTouchOnHit[string, *OPSession](),
	)
	// Start the janitor so expired authorization sessions are evicted and
	// the nominal TTL actually bounds memory use; stopped from OP.Close.
	go cache.Start()
	return &defaultOPStorage{
		cache: cache,
		ttl:   defaultOPSessionTTL,
	}
}

// Stop halts the TTL cache janitor goroutine. Called from OP.Close.
func (s *defaultOPStorage) Stop() {
	s.cache.Stop()
}

// Put stores opSession keyed by its ID.
func (s *defaultOPStorage) Put(_ context.Context, opSession *OPSession) error {
	s.cache.Set(opSession.ID, opSession, s.ttl)
	return nil
}

// Get returns the OPSession with id, or an error if none is stored
// (or it has expired).
func (s *defaultOPStorage) Get(_ context.Context, id string) (*OPSession, error) {
	item := s.cache.Get(id)
	if item == nil {
		return nil, fmt.Errorf("credbridge/op: no session %q", id)
	}
	return item.Value(), nil
}

// Delete removes the OPSession with id (no-op if absent).
func (s *defaultOPStorage) Delete(_ context.Context, id string) error {
	s.cache.Delete(id)
	return nil
}
