package credbridge_test

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verifierOP(t *testing.T, verifier credbridge.CredentialVerifier) *credbridge.OP {
	t.Helper()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		ClientValidator:       allowAnyClient,
		CredentialVerifier:    verifier,
		Signer:                testsigner.MustNew(),
		DCQLQuerySupported:    true,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"ehic": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:ehic"}, SubjectClaim: []string{"ehic_number"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	t.Cleanup(op.Close)
	return op
}

func verifierToken() string {
	return testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{"vct": "urn:t:ehic", "ehic_number": "1"})
}

// §5.3 step 4: an OP without a verifier would issue assertions from
// credentials it never verified, so construction must fail.
func TestOP_RequiresCredentialVerifier(t *testing.T) {
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	_, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		ClientValidator:       allowAnyClient,
		Signer:                testsigner.MustNew(),
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"ehic": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:ehic"}, SubjectClaim: []string{"ehic_number"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	assert.ErrorContains(t, err, "CredentialVerifier")
}

// §6.3: a credential that fails verification must not reach the ID Token.
func TestOP_RejectedCredentialIsNotAccepted(t *testing.T) {
	op := verifierOP(t, credbridge.CredentialVerifierFunc(func(context.Context, credbridge.CredentialVerificationRequest) (*credbridge.CredentialVerification, error) {
		return nil, errors.New("bad signature")
	}))
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
	_, err := respond(op, sess, map[string][]string{"ehic": {verifierToken()}})
	assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied)
}

// The verifier must see the session nonce and the OP's client id, so it
// can check the holder-binding proof against them (§7.1).
func TestOP_VerifierReceivesSessionBinding(t *testing.T) {
	var got credbridge.CredentialVerificationRequest
	op := verifierOP(t, credbridge.CredentialVerifierFunc(func(_ context.Context, req credbridge.CredentialVerificationRequest) (*credbridge.CredentialVerification, error) {
		got = req
		return &credbridge.CredentialVerification{TrustStatus: credbridge.TrustStatusValid, HolderBinding: credbridge.HolderBindingKey}, nil
	}))
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
	token := verifierToken()
	_, err := respond(op, sess, map[string][]string{"ehic": {token}})
	require.NoError(t, err)
	assert.Equal(t, token, got.Token)
	assert.Equal(t, sess.Nonce, got.Nonce)
	assert.Equal(t, "https://op.example.org", got.ClientID)
	assert.Equal(t, "ehic", got.Query.ID)
}

// A verifier result lands in the entry; nothing is invented.
func TestOP_EntryCarriesVerifiedMetadata(t *testing.T) {
	op := verifierOP(t, credbridge.CredentialVerifierFunc(func(context.Context, credbridge.CredentialVerificationRequest) (*credbridge.CredentialVerification, error) {
		return &credbridge.CredentialVerification{
			Issuer:           "https://issuer.example",
			TrustStatus:      credbridge.TrustStatusValid,
			HolderBinding:    credbridge.HolderBindingKey,
			ProtectedHeaders: map[string]any{"alg": "ES256"},
		}, nil
	}))
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
	res, err := respond(op, sess, map[string][]string{"ehic": {verifierToken()}})
	require.NoError(t, err)
	entry := res.Entries["ehic"][0]
	assert.Equal(t, "https://issuer.example", entry.Issuer)
	assert.NotZero(t, entry.VerifiedAt)
	assert.Equal(t, credbridge.TrustStatusValid, entry.Verification.TrustStatus)
	assert.Equal(t, credbridge.HolderBindingKey, entry.Verification.HolderBinding)
	assert.Equal(t, map[string]any{"alg": "ES256"}, entry.Verification.ProtectedHeaders)
}

// A verifier cannot weaken the RP's constraints: required cryptographic
// holder binding, a registered status, and a non-invalid status.
func TestOP_VerifierResultIsChecked(t *testing.T) {
	cases := map[string]*credbridge.CredentialVerification{
		"no holder binding":      {TrustStatus: credbridge.TrustStatusValid},
		"wrong holder binding":   {TrustStatus: credbridge.TrustStatusValid, HolderBinding: credbridge.HolderBindingPIN},
		"unregistered status":    {TrustStatus: "made_up", HolderBinding: credbridge.HolderBindingKey},
		"invalid status":         {TrustStatus: credbridge.TrustStatusInvalid, HolderBinding: credbridge.HolderBindingKey},
		"unregistered binding":   {TrustStatus: credbridge.TrustStatusValid, HolderBinding: "smell_test"},
		"nil result":             nil,
		"empty status":           {HolderBinding: credbridge.HolderBindingKey},
		"status without binding": {TrustStatus: credbridge.TrustStatusNotChecked},
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			op := verifierOP(t, credbridge.CredentialVerifierFunc(func(context.Context, credbridge.CredentialVerificationRequest) (*credbridge.CredentialVerification, error) {
				return result, nil
			}))
			sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
			_, err := respond(op, sess, map[string][]string{"ehic": {verifierToken()}})
			assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied)
		})
	}
}
