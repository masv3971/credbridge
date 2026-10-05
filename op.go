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
	// values (Section 5.5 → OIDC Core §8.1). If empty, subject
	// derivation returns the raw subject value verbatim.
	PairwiseSalt []byte

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
}

// validate reports the first missing or malformed required field on c.
func (c OPConfig) validate() error {
	if c.Issuer == "" {
		return errors.New("credbridge/op: OPConfig.Issuer is required")
	}
	if _, err := url.Parse(c.Issuer); err != nil {
		return fmt.Errorf("credbridge/op: OPConfig.Issuer invalid: %w", err)
	}
	if c.AuthorizationEndpoint == "" {
		return errors.New("credbridge/op: OPConfig.AuthorizationEndpoint is required")
	}
	if c.TokenEndpoint == "" {
		return errors.New("credbridge/op: OPConfig.TokenEndpoint is required")
	}
	if c.Signer == nil {
		return errors.New("credbridge/op: OPConfig.Signer is required")
	}
	if len(c.CredentialPresentations) == 0 {
		return errors.New("credbridge/op: OPConfig.CredentialPresentations must contain at least one entry")
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
	return &defaultOPStorage{
		cache: ttlcache.New[string, *OPSession](
			ttlcache.WithTTL[string, *OPSession](defaultOPSessionTTL),
			ttlcache.WithDisableTouchOnHit[string, *OPSession](),
		),
		ttl: defaultOPSessionTTL,
	}
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
