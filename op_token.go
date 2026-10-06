package credbridge

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/golang-jwt/jwt/v5"
)

// IssueIDToken produces a signed ID Token containing the sub claim and
// the presented_credential_sets claim (Sections 5.1, 5.5, 7.1).
//
// After the token is issued the session-level credential payload is
// dropped from the session store, honouring the Section 6.4 fresh-
// presentation retention rule for the ID Token delivery channel.
func (o *OP) IssueIDToken(ctx context.Context, opSession *OPSession, result *OPPresentationResult, opts OPTokenOptions) (string, error) {
	if opSession == nil {
		return "", fmt.Errorf("%w: nil session", ErrOPAccessDenied)
	}
	if opts.TokenLifetimeSeconds < 0 {
		return "", fmt.Errorf("%w: TokenLifetimeSeconds must not be negative", ErrOPInvalidRequest)
	}
	// Atomically consume the stored session: retrieving then deleting it
	// before minting ensures a stale, expired, or already-consumed
	// session cannot be replayed to mint a second token. The stored copy
	// (not the caller-supplied pointer) is the source of truth for the
	// minted claims.
	stored, err := o.storage.Get(ctx, opSession.ID)
	if err != nil {
		return "", fmt.Errorf("%w: session %q not found or already consumed: %v", ErrOPAccessDenied, opSession.ID, err)
	}
	if err := o.storage.Delete(ctx, stored.ID); err != nil {
		return "", fmt.Errorf("credbridge/op: consume session: %w", err)
	}
	opSession = stored

	sets, err := o.assemblePresentedCredentialSets(result)
	if err != nil {
		return "", err
	}
	sub, err := o.deriveSub(opSession, sets)
	if err != nil {
		return "", err
	}
	now := o.now().Unix()
	if opts.TokenLifetimeSeconds == 0 {
		opts.TokenLifetimeSeconds = 300
	}
	body := jwt.MapClaims{
		"iss":                        o.cfg.Issuer,
		"aud":                        opSession.ClientID,
		"sub":                        sub,
		"iat":                        now,
		"exp":                        now + int64(opts.TokenLifetimeSeconds),
		"nonce":                      opSession.Nonce,
		PresentedCredentialSetsClaim: sets,
	}
	header := jwt.MapClaims{"typ": "JWT"}
	tok, err := jose.MakeJWT(ctx, header, body, o.cfg.Signer)
	if err != nil {
		return "", fmt.Errorf("credbridge/op: sign id token: %w", err)
	}
	return tok, nil
}

// OPTokenOptions tune ID Token / UserInfo issuance.
type OPTokenOptions struct {
	// TokenLifetimeSeconds sets exp − iat. Defaults to 300 (5 minutes).
	// Negative values are rejected.
	TokenLifetimeSeconds int
}

// UserInfoPayload assembles the JSON body the OP returns from
// /userinfo. Callers that use signed UserInfo responses can pass the
// returned map to jose.MakeJWT themselves.
func (o *OP) UserInfoPayload(opSession *OPSession, result *OPPresentationResult) (map[string]any, error) {
	sets, err := o.assemblePresentedCredentialSets(result)
	if err != nil {
		return nil, err
	}
	sub, err := o.deriveSub(opSession, sets)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sub":                        sub,
		PresentedCredentialSetsClaim: sets,
	}, nil
}
