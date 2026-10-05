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
	sets := o.assemblePresentedCredentialSets(result)
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
	if !opts.RetainForUserInfo {
		if err := o.storage.Delete(ctx, opSession.ID); err != nil {
			return tok, fmt.Errorf("credbridge/op: id token issued but session cleanup failed: %w", err)
		}
	}
	return tok, nil
}

// OPTokenOptions tune ID Token / UserInfo issuance.
type OPTokenOptions struct {
	// TokenLifetimeSeconds sets exp − iat. Defaults to 300 (5 minutes).
	TokenLifetimeSeconds int
	// RetainForUserInfo asks the OP to keep the session (and its
	// verified credential claims) available for later UserInfo requests
	// authorised by the same access token, subject to §6.4.
	RetainForUserInfo bool
}

// UserInfoPayload assembles the JSON body the OP returns from
// /userinfo. Callers that use signed UserInfo responses can pass the
// returned map to jose.MakeJWT themselves.
func (o *OP) UserInfoPayload(opSession *OPSession, result *OPPresentationResult) (map[string]any, error) {
	sets := o.assemblePresentedCredentialSets(result)
	sub, err := o.deriveSub(opSession, sets)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sub":                        sub,
		PresentedCredentialSetsClaim: sets,
	}, nil
}
