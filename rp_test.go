package credbridge_test

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Appendix C: JSON-type-strict, no normalization, arrays element-wise.
func TestMatchValue(t *testing.T) {
	cases := []struct {
		name           string
		disclosed, exp any
		want           bool
	}{
		{"string equal", "SE", "SE", true},
		{"string type mismatch", "1", 1, false},
		{"int matches equal float", 1, 1.0, true},
		{"int type mismatch string", 1, "1", false},
		{"bool true", true, true, true},
		{"bool false vs true", false, true, false},
		{"array equal", []any{"SE", "NO"}, []any{"SE", "NO"}, true},
		{"array element mismatch", []any{"SE"}, []any{"NO"}, false},
		{"object equal", map[string]any{"k": "v"}, map[string]any{"k": "v"}, true},
		{"object missing member", map[string]any{"k": "v"}, map[string]any{"k": "v", "other": 1}, false},
		{"null equal", nil, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, credbridge.MatchValue(c.disclosed, c.exp))
		})
	}
}

// §5.1.2 crit: absent members and unknown members must fail.
func TestEvaluateCrit(t *testing.T) {
	entry := credbridge.CredentialEntry{
		Verification: &credbridge.Verification{
			TrustStatus: credbridge.TrustStatusSuspended,
			Crit:        []string{"trust_status"},
		},
	}
	assert.NoError(t, credbridge.EvaluateCrit(entry), "standard member must satisfy crit")

	entry.Verification.Crit = []string{"missing_member"}
	assert.ErrorIs(t, credbridge.EvaluateCrit(entry), credbridge.ErrCritUnknownMember)

	entry.Verification.Crit = []string{"crit"}
	assert.Error(t, credbridge.EvaluateCrit(entry), `crit containing "crit" must fail`)

	entry.Verification.Crit = []string{"custom"}
	entry.Verification.AdditionalMembers = map[string]any{"custom": "value"}
	assert.ErrorIs(t, credbridge.EvaluateCrit(entry), credbridge.ErrCritUnknownMember,
		"undeclared custom member must fail")
	assert.NoError(t, credbridge.EvaluateCrit(entry, "custom"),
		"declared custom member must satisfy crit")

	// §5.1.2: an omitted verification member must default to
	// trust_status=not_checked and satisfy an empty crit.
	entryNoVer := credbridge.CredentialEntry{Type: []string{"vc"}}
	assert.NoError(t, credbridge.EvaluateCrit(entryNoVer), "nil Verification must satisfy empty crit")
	assert.Equal(t, credbridge.TrustStatusNotChecked, entryNoVer.EffectiveVerification().TrustStatus)
}

// §5.1: UserInfo carries the same presented_credential_sets shape as
// the ID Token. Exercises OP.UserInfoPayload and RP.FetchUserInfoClaims.
func TestUserInfoRoundTrip(t *testing.T) {
	ctx := t.Context()
	sig := testsigner.MustNew()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(ctx, credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		Signer:                sig,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"ehic": {
				Format:       openid4vp.FormatSDJWTVC,
				Type:         []string{"urn:eu.europa.ec.eudi:ehic:1"},
				SubjectClaim: []string{"ehic_number"},
			},
		},
		PairwiseSalt: []byte("test-salt"),
	})
	require.NoError(t, err, "NewOP")
	defer op.Close()

	opSession, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID:    "https://rp.example.org",
		RedirectURI: "https://rp.example.org/cb",
		Nonce:       "n",
		Scopes:      []string{"ehic"},
	})
	require.NoError(t, err, "StartAuthorization")
	token := testsigner.MustIssueJWT(sig, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:ehic:1",
		"ehic_number": "1234567890",
	})
	result, err := op.HandleWalletResponse(ctx, opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"ehic": {token}},
		State:   opSession.State,
	}, nil)
	require.NoError(t, err, "HandleWalletResponse")
	payload, err := op.UserInfoPayload(opSession, result)
	require.NoError(t, err, "UserInfoPayload")
	body, err := json.Marshal(payload)
	require.NoError(t, err, "marshal")

	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL:   "https://op.example.org",
		ClientID:    "https://rp.example.org",
		RedirectURI: "https://rp.example.org/cb",
	})
	require.NoError(t, err, "NewRP")
	claims, err := rp.FetchUserInfoClaims(body, "")
	require.NoError(t, err, "FetchUserInfoClaims")
	entry, ok := claims.FirstEntry("", "ehic")
	require.True(t, ok, "ehic entry missing from UserInfo")
	assert.Equal(t, "1234567890", entry.Claims["ehic_number"])
}
