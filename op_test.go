package credbridge_test

import (
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Section 7.1: the wallet nonce MUST be byte-identical to the OIDC nonce.
func TestOP_NonceIsByteIdentical(t *testing.T) {
	ctx := t.Context()
	op := mustOP(t)
	defer op.Close()

	opSession, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID:    "https://rp.example.org",
		RedirectURI: "https://rp.example.org/cb",
		Nonce:       "n-0S6_WzA2Mj",
		Scopes:      []string{"openid", "ehic"},
	})
	require.NoError(t, err, "StartAuthorization")
	req, err := op.BuildWalletRequest(ctx, opSession, "https://op.example.org/response")
	require.NoError(t, err, "BuildWalletRequest")
	assert.Equal(t, "n-0S6_WzA2Mj", req.Nonce)
}

// Section 5.4: when the RP asks for a specific claim path, the OP MUST
// suppress unrequested claims disclosed by the wallet.
func TestOP_DataMinimisation(t *testing.T) {
	ctx := t.Context()
	sig := testsigner.MustNew()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(ctx, credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		Signer:                sig,
		DCQLQuerySupported:    true,
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
		ClientID:    "rp",
		RedirectURI: "https://rp.example.org/cb",
		Nonce:       "n",
		Scopes:      []string{"ehic"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "ehic",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("ehic_number")}},
		}}},
	})
	require.NoError(t, err, "StartAuthorization")
	token := testsigner.MustIssueJWT(sig, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:ehic:1",
		"ehic_number": "1234567890",
		"secret":      "should-not-leak",
	})
	result, err := op.HandleWalletResponse(ctx, opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"ehic": {token}},
		State:   opSession.State,
	}, nil)
	require.NoError(t, err, "HandleWalletResponse")
	entry := result.Entries["ehic"][0]
	assert.NotContains(t, entry.Claims, "secret", "unrequested claim leaked")
	assert.Contains(t, entry.Claims, "ehic_number", "requested claim missing")
}

// Appendix A.2: RP-supplied ids beginning with the reserved prefix MUST
// be rejected.
func TestOP_ReservedPrefixRejected(t *testing.T) {
	ctx := t.Context()
	op := mustDCQLOP(t)
	defer op.Close()

	_, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID:    "rp",
		RedirectURI: "https://rp.example.org/cb",
		Nonce:       "n",
		Scopes:      []string{"ehic"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     credbridge.BridgeIDPrefix + "ehic",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		}}},
	})
	assert.ErrorIs(t, err, credbridge.ErrOPBridgePrefixReserved)
}

// §4.1.2: credential_sets MUST carry an id; missing/blank/non-conforming
// or duplicate ids MUST cause invalid_request.
func TestOP_CredentialSetsRequireID(t *testing.T) {
	ctx := t.Context()
	op := mustDCQLOP(t)
	defer op.Close()

	required := false
	base := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "ehic",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		}},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{Options: [][]string{{"ehic"}}, Required: &required},
		},
	}
	req := credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"ehic"}, DCQLQuery: base,
	}
	_, err := op.StartAuthorization(ctx, req)
	assert.ErrorIs(t, err, credbridge.ErrOPInvalidRequest, "missing credential_sets id")

	req.CredentialSetIDs = []string{"bad:id"}
	_, err = op.StartAuthorization(ctx, req)
	assert.ErrorIs(t, err, credbridge.ErrOPInvalidRequest, "id violating DCQL charset")

	twoSets := *base
	twoSets.CredentialSets = []openid4vp.CredentialSetQuery{
		{Options: [][]string{{"ehic"}}, Required: &required},
		{Options: [][]string{{"ehic"}}, Required: &required},
	}
	req.DCQLQuery = &twoSets
	req.CredentialSetIDs = []string{"a", "a"}
	_, err = op.StartAuthorization(ctx, req)
	assert.ErrorIs(t, err, credbridge.ErrOPInvalidRequest, "duplicate credential_set ids")
}

// §4.1.2: RP-supplied credential_query ids must conform to the DCQL charset.
func TestOP_RPQueryIDMustBeDCQLConforming(t *testing.T) {
	ctx := t.Context()
	op := mustDCQLOP(t)
	defer op.Close()

	_, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"ehic"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "not.allowed",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		}}},
	})
	assert.ErrorIs(t, err, credbridge.ErrOPInvalidRequest)
}

func mustOP(t *testing.T) *credbridge.OP {
	t.Helper()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		Signer:                testsigner.MustNew(),
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
	return op
}

func mustDCQLOP(t *testing.T) *credbridge.OP {
	t.Helper()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		Signer:                testsigner.MustNew(),
		DCQLQuerySupported:    true,
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
	return op
}
