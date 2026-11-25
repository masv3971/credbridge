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

func opWith(t *testing.T, st credbridge.OPSubjectType, pres map[string]credbridge.OPCredentialTypeConfig) *credbridge.OP {
	t.Helper()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                  "https://op.example.org",
		AuthorizationEndpoint:   "https://op.example.org/authorize",
		TokenEndpoint:           "https://op.example.org/token",
		ClientValidator:         allowAnyClient,
		Signer:                  testsigner.MustNew(),
		DCQLQuerySupported:      true,
		SubjectType:             st,
		CredentialPresentations: pres,
		PairwiseSalt:            []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	t.Cleanup(op.Close)
	return op
}

func claimPaths(cq openid4vp.CredentialQuery) [][]string {
	var out [][]string
	for _, cl := range cq.Claims {
		var p []string
		for _, s := range cl.Path {
			p = append(p, *s)
		}
		out = append(out, p)
	}
	return out
}

// A null or empty subject must fail in pairwise mode instead of hashing
// every such holder to one shared sub.
func TestOP_PairwiseSubjectRejectsNullAndEmpty(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePairwise)
	sig := testsigner.MustNew()
	for name, v := range map[string]any{"null": nil, "empty": ""} {
		sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
		tok := testsigner.MustIssueJWT(sig, map[string]any{"vct": "urn:t:ehic", "ehic_number": v})
		res, err := respond(op, sess, map[string][]string{"ehic": {tok}})
		require.NoError(t, err, name)
		_, err = op.UserInfoPayload(sess, res)
		assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied, name)
	}
}

// The same identifier value in two credential types must not give the same
// pairwise sub for one RP.
func TestOP_PairwiseSubIsNamespacedByCredentialType(t *testing.T) {
	op := opWith(t, credbridge.OPSubjectTypePairwise, map[string]credbridge.OPCredentialTypeConfig{
		"a": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:a"}, SubjectClaim: []string{"id"}},
		"b": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:b"}, SubjectClaim: []string{"id"}},
	})
	sig := testsigner.MustNew()
	sub := func(scope, vct string) string {
		sess, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
			ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n", Scopes: []string{scope},
		})
		require.NoError(t, err)
		tok := testsigner.MustIssueJWT(sig, map[string]any{"vct": vct, "id": "123"})
		res, err := respond(op, sess, map[string][]string{scope: {tok}})
		require.NoError(t, err)
		payload, err := op.UserInfoPayload(sess, res)
		require.NoError(t, err)
		return payload["sub"].(string)
	}
	assert.NotEqual(t, sub("a", "urn:t:a"), sub("b", "urn:t:b"))
	assert.Equal(t, sub("a", "urn:t:a"), sub("a", "urn:t:a"), "derivation stays deterministic")
}

// ["a,b"] and ["a","b"] are different W3C types and must not collide.
func TestOP_TypeKeyKeepsElementBoundaries(t *testing.T) {
	op := opWith(t, credbridge.OPSubjectTypePublic, map[string]credbridge.OPCredentialTypeConfig{
		"one": {Format: openid4vp.FormatJwtVCJson, Type: []string{"VerifiableCredential", "a,b"}, SubjectClaim: []string{"id"}},
		"two": {Format: openid4vp.FormatJwtVCJson, Type: []string{"VerifiableCredential", "a", "b"}, SubjectClaim: []string{"id"}},
	})
	cq := openid4vp.CredentialQuery{
		ID: "q", Format: openid4vp.FormatJwtVCJson,
		Meta: openid4vp.MetaQuery{TypeValues: [][]string{{"VerifiableCredential", "a", "b"}}},
	}
	sess := dcqlSession(t, op, []string{"one", "two"}, cq)
	require.Len(t, sess.DCQL.Credentials, 2)
	assert.Equal(t, "two", sess.DCQL.Credentials[0].Scope, "resolved to the scope with the same elements")
}

// The wallet must be asked for the subject claim even when the RP requests
// other claims only, without relaying it to the RP.
func TestOP_SubjectClaimRequestedFromWallet(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic",
		openid4vp.ClaimQuery{Path: openid4vp.StringPath("expiry")}))
	req, err := op.BuildWalletRequest(t.Context(), sess, "https://op.example.org/resp")
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"expiry"}, {"ehic_number"}}, claimPaths(req.DCQL.Credentials[0]))

	tok := testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{
		"vct": "urn:t:ehic", "ehic_number": "E-1", "expiry": "2030",
	})
	res, err := respond(op, sess, map[string][]string{"ehic": {tok}})
	require.NoError(t, err)
	claims := res.Entries["ehic"][0].Claims
	assert.Equal(t, "2030", claims["expiry"])
	assert.NotContains(t, claims, "ehic_number", "subject claim is not relayed unless requested")
	payload, err := op.UserInfoPayload(sess, res)
	require.NoError(t, err)
	assert.Equal(t, "E-1", payload["sub"])
}

// With claim_sets the subject claim joins every option, and the stored
// query keeps the RP's own options.
func TestOP_SubjectClaimAddedToEveryClaimSetOption(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	q := ehicQuery("ehic",
		openid4vp.ClaimQuery{ID: "a", Path: openid4vp.StringPath("expiry")},
		openid4vp.ClaimQuery{ID: "b", Path: openid4vp.StringPath("country")},
	)
	q.ClaimSet = [][]string{{"a"}, {"b"}}
	sess := dcqlSession(t, op, []string{"ehic"}, q)
	req, err := op.BuildWalletRequest(t.Context(), sess, "https://op.example.org/resp")
	require.NoError(t, err)
	wallet := req.DCQL.Credentials[0]
	require.Len(t, wallet.ClaimSet, 2)
	subjectID := wallet.ClaimSet[0][1]
	assert.Equal(t, []string{"a", subjectID}, wallet.ClaimSet[0])
	assert.Equal(t, []string{"b", subjectID}, wallet.ClaimSet[1])
	assert.Contains(t, claimPaths(wallet), []string{"ehic_number"})
	assert.Equal(t, [][]string{{"a"}, {"b"}}, sess.DCQL.Credentials[0].ClaimSets, "RP options are not mutated")
}

// jwt_vc_json: claims live under vc.credentialSubject, and JWT envelope
// claims must be neither matched nor relayed.
func TestOP_JWTVCJSONUsesCredentialSubject(t *testing.T) {
	op := opWith(t, credbridge.OPSubjectTypePublic, map[string]credbridge.OPCredentialTypeConfig{
		"degree": {Format: openid4vp.FormatJwtVCJson, Type: []string{"VerifiableCredential", "Degree"}, SubjectClaim: []string{"degree", "name"}},
	})
	q := openid4vp.CredentialQuery{
		ID: "degree", Format: openid4vp.FormatJwtVCJson,
		Meta:   openid4vp.MetaQuery{TypeValues: [][]string{{"VerifiableCredential", "Degree"}}},
		Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("degree", "name")}},
	}
	sess := dcqlSession(t, op, []string{"degree"}, q)
	tok := testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{
		"iss": "https://issuer.example",
		"vc": map[string]any{
			"type":              []any{"VerifiableCredential", "Degree"},
			"credentialSubject": map[string]any{"degree": map[string]any{"name": "BSc", "level": "1"}, "other": "x"},
		},
	})
	res, err := respond(op, sess, map[string][]string{"degree": {tok}})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"degree": map[string]any{"name": "BSc"}}, res.Entries["degree"][0].Claims)
	payload, err := op.UserInfoPayload(sess, res)
	require.NoError(t, err)
	assert.Equal(t, "BSc", payload["sub"])

	flat := testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{"degree": map[string]any{"name": "BSc"}})
	_, err = respond(op, dcqlSession(t, op, []string{"degree"}, q), map[string][]string{"degree": {flat}})
	assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied, "a JWT without a credential is not a jwt_vc_json credential")
}

func TestOP_EmptyClaimPathRejected(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	_, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n", Scopes: []string{"ehic"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{ehicQuery("ehic", openid4vp.ClaimQuery{})}},
	})
	assert.ErrorIs(t, err, credbridge.ErrOPInvalidRequest)
}

func TestCredentialEntry_NullClaimsOrNamespacesRejected(t *testing.T) {
	var e credbridge.CredentialEntry
	assert.Error(t, json.Unmarshal([]byte(`{"type":["vc"],"claims":null,"namespaces":{}}`), &e))
	assert.Error(t, json.Unmarshal([]byte(`{"type":["vc"],"claims":{},"namespaces":null}`), &e))
	assert.NoError(t, json.Unmarshal([]byte(`{"type":["vc"],"claims":{}}`), &e))
}

// The satisfied alternatives of every credential_sets entry end up in the
// one response Credential Set, and no credential_set_id is emitted.
func TestOP_SingleResponseSetMergesSatisfiedGroups(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	sig := testsigner.MustNew()
	yes := true
	pidQuery := openid4vp.CredentialQuery{
		ID: "pid", Format: openid4vp.FormatSDJWTVC,
		Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:t:pid"}},
		Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("personal_id")}},
	}
	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{pidQuery, ehicQuery("ehic", openid4vp.ClaimQuery{Path: openid4vp.StringPath("ehic_number")})},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{Options: [][]string{{"pid"}}, Required: &yes},
			{Options: [][]string{{"ehic"}}, Required: &yes},
		},
	}
	start := func() *credbridge.OPSession {
		sess, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
			ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
			Scopes: []string{"pid", "ehic"}, DCQLQuery: dcql,
		})
		require.NoError(t, err)
		return sess
	}
	pidTok := testsigner.MustIssueJWT(sig, map[string]any{"vct": "urn:t:pid", "personal_id": "P-1"})
	ehicTok := testsigner.MustIssueJWT(sig, map[string]any{"vct": "urn:t:ehic", "ehic_number": "E-1"})

	sess := start()
	res, err := respond(op, sess, map[string][]string{"pid": {pidTok}, "ehic": {ehicTok}})
	require.NoError(t, err)
	payload, err := op.UserInfoPayload(sess, res)
	require.NoError(t, err)
	sets, ok := payload[credbridge.PresentedCredentialSetsClaim].(credbridge.PresentedCredentialSets)
	require.True(t, ok)
	require.Len(t, sets, 1, "exactly one Credential Set")
	assert.Contains(t, sets[0].Credentials, "pid")
	assert.Contains(t, sets[0].Credentials, "ehic")
	raw, err := json.Marshal(sets)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "credential_set_id")

	_, err = respond(op, start(), map[string][]string{"ehic": {ehicTok}})
	assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied, "required credential_sets entry unsatisfied")
}
