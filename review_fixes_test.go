package credbridge_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func twoScopeOP(t *testing.T, subjectType credbridge.OPSubjectType) *credbridge.OP {
	t.Helper()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		ClientValidator:       allowAnyClient,
		CredentialVerifier:    acceptVerifier,
		Signer:                testsigner.MustNew(),
		DCQLQuerySupported:    true,
		SubjectType:           subjectType,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"pid":  {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:pid"}, SubjectClaim: []string{"personal_id"}},
			"ehic": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:ehic"}, SubjectClaim: []string{"ehic_number"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	t.Cleanup(op.Close)
	return op
}

func dcqlSession(t *testing.T, op *credbridge.OP, scopes []string, cqs ...openid4vp.CredentialQuery) *credbridge.OPSession {
	t.Helper()
	sess, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: scopes, DCQLQuery: &openid4vp.DCQL{Credentials: cqs},
	})
	require.NoError(t, err, "StartAuthorization")
	return sess
}

func ehicQuery(id string, claims ...openid4vp.ClaimQuery) openid4vp.CredentialQuery {
	return openid4vp.CredentialQuery{
		ID: id, Format: openid4vp.FormatSDJWTVC,
		Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:t:ehic"}},
		Claims: claims,
	}
}

func respond(op *credbridge.OP, sess *credbridge.OPSession, tokens map[string][]string) (*credbridge.OPPresentationResult, error) {
	return op.HandleWalletResponse(context.Background(), sess, &openid4vp.VPResponse{VPToken: tokens, State: sess.State}, nil)
}

// A numeric subject beyond 2^53 cannot be told apart from its neighbour
// after float64 decoding, so it must be rejected rather than hashed.
func TestOP_PairwiseSubjectRejectsLossyNumber(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePairwise)
	sig := testsigner.MustNew()
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
	tok := testsigner.MustIssueJWT(sig, map[string]any{"vct": "urn:t:ehic", "ehic_number": float64(1 << 53)})
	res, err := respond(op, sess, map[string][]string{"ehic": {tok}})
	require.NoError(t, err)
	_, err = op.UserInfoPayload(sess, res)
	assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied)

	sess = dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
	tok = testsigner.MustIssueJWT(sig, map[string]any{"vct": "urn:t:ehic", "ehic_number": float64(12345)})
	res, err = respond(op, sess, map[string][]string{"ehic": {tok}})
	require.NoError(t, err)
	_, err = op.UserInfoPayload(sess, res)
	assert.NoError(t, err, "safe integer subject")
}

// A query id equal to another scope's name must not select that scope's
// subject claim.
func TestOP_SubjectUsesScopeBoundToQuery(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("pid"))
	tok := testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{
		"vct": "urn:t:ehic", "ehic_number": "E-1", "personal_id": "WRONG",
	})
	res, err := respond(op, sess, map[string][]string{"pid": {tok}})
	require.NoError(t, err)
	payload, err := op.UserInfoPayload(sess, res)
	require.NoError(t, err)
	assert.Equal(t, "E-1", payload["sub"])
}

// Without claim_sets every requested path must be disclosed.
func TestOP_RequestedClaimMustBeDisclosed(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic",
		openid4vp.ClaimQuery{Path: openid4vp.StringPath("ehic_number")},
		openid4vp.ClaimQuery{Path: openid4vp.StringPath("expiry")},
	))
	tok := testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{"vct": "urn:t:ehic", "ehic_number": "E-1"})
	_, err := respond(op, sess, map[string][]string{"ehic": {tok}})
	assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied)
}

// A disclosure that satisfies one claim_sets option is accepted even when
// another option's claim is absent or mismatched.
func TestOP_ClaimSetsEvaluatedPerOption(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	q := ehicQuery("ehic",
		openid4vp.ClaimQuery{ID: "a", Path: openid4vp.StringPath("ehic_number")},
		openid4vp.ClaimQuery{ID: "b", Path: openid4vp.StringPath("country"), Values: []any{"SE"}},
	)
	q.ClaimSet = [][]string{{"b"}, {"a"}}
	sess := dcqlSession(t, op, []string{"ehic"}, q)
	tok := testsigner.MustIssueJWT(testsigner.MustNew(), map[string]any{
		"vct": "urn:t:ehic", "ehic_number": "E-1", "country": "NO",
	})
	res, err := respond(op, sess, map[string][]string{"ehic": {tok}})
	require.NoError(t, err)
	claims := res.Entries["ehic"][0].Claims
	assert.Equal(t, "E-1", claims["ehic_number"])
	assert.NotContains(t, claims, "country")
}

// "multiple" defaults to false: it is forwarded when true and enforced.
func TestOP_MultipleForwardedAndEnforced(t *testing.T) {
	op := twoScopeOP(t, credbridge.OPSubjectTypePublic)
	sig := testsigner.MustNew()
	tok := func(n string) string {
		return testsigner.MustIssueJWT(sig, map[string]any{"vct": "urn:t:ehic", "ehic_number": n})
	}

	sess := dcqlSession(t, op, []string{"ehic"}, ehicQuery("ehic"))
	req, err := op.BuildWalletRequest(t.Context(), sess, "https://op.example.org/resp")
	require.NoError(t, err)
	assert.Nil(t, req.DCQL.Credentials[0].Multiple)
	_, err = respond(op, sess, map[string][]string{"ehic": {tok("1"), tok("2")}})
	assert.ErrorIs(t, err, credbridge.ErrOPAccessDenied, "two tokens without multiple")

	yes := true
	q := ehicQuery("ehic")
	q.Multiple = &yes
	sess = dcqlSession(t, op, []string{"ehic"}, q)
	req, err = op.BuildWalletRequest(t.Context(), sess, "https://op.example.org/resp")
	require.NoError(t, err)
	require.NotNil(t, req.DCQL.Credentials[0].Multiple)
	assert.True(t, *req.DCQL.Credentials[0].Multiple)
	res, err := respond(op, sess, map[string][]string{"ehic": {tok("1"), tok("2")}})
	require.NoError(t, err)
	assert.Len(t, res.Entries["ehic"], 2)
}

// type_values alternatives are forwarded unchanged, and alternatives that
// name a different credential type than the bound scope are rejected.
func TestOP_TypeValuesAlternatives(t *testing.T) {
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		ClientValidator:       allowAnyClient,
		CredentialVerifier:    acceptVerifier,
		Signer:                testsigner.MustNew(),
		DCQLQuerySupported:    true,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"degree": {Format: openid4vp.FormatJwtVCJson, Type: []string{"VerifiableCredential", "Degree"}, SubjectClaim: []string{"degree"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err)
	defer op.Close()

	same := []string{"VerifiableCredential", "Degree"}
	cq := openid4vp.CredentialQuery{
		ID: "degree", Format: openid4vp.FormatJwtVCJson,
		Meta: openid4vp.MetaQuery{TypeValues: [][]string{same, same}},
	}
	sess := dcqlSession(t, op, []string{"degree"}, cq)
	req, err := op.BuildWalletRequest(t.Context(), sess, "https://op.example.org/resp")
	require.NoError(t, err)
	assert.Len(t, req.DCQL.Credentials[0].Meta.TypeValues, 2, "alternatives forwarded")

	cq.Meta.TypeValues = [][]string{same, {"VerifiableCredential", "Other"}}
	_, err = op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"degree"}, DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{cq}},
	})
	assert.ErrorIs(t, err, credbridge.ErrOPInvalidRequest)
}

// The extractor returns only credentialSubject for a W3C document, so the
// credential type must be read from the document itself.
func TestOP_W3CDocumentTypeFromDocument(t *testing.T) {
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		ClientValidator:       allowAnyClient,
		CredentialVerifier:    acceptVerifier,
		Signer:                testsigner.MustNew(),
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"degree": {Format: openid4vp.FormatLdpVCDCQL, Type: []string{"VerifiableCredential", "Degree"}, SubjectClaim: []string{"degree"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err)
	defer op.Close()

	sess, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n", Scopes: []string{"degree"},
	})
	require.NoError(t, err)
	doc, err := json.Marshal(map[string]any{
		"@context":          []string{"https://www.w3.org/ns/credentials/v2"},
		"type":              []string{"VerifiableCredential", "Degree", "Extra"},
		"credentialSubject": map[string]any{"degree": "BSc"},
	})
	require.NoError(t, err)
	res, err := respond(op, sess, map[string][]string{"degree": {string(doc)}})
	require.NoError(t, err)
	assert.Equal(t, []string{"VerifiableCredential", "Degree", "Extra"}, res.Entries["degree"][0].Type)
}

func TestMatchValue_JSONNumber(t *testing.T) {
	assert.True(t, credbridge.MatchValue(float64(18), json.Number("18")))
	assert.True(t, credbridge.MatchValue(json.Number("18"), int64(18)))
	assert.False(t, credbridge.MatchValue(float64(19), json.Number("18")))
	assert.False(t, credbridge.MatchValue(json.Number("9007199254740993"), json.Number("9007199254740992")))
	assert.False(t, credbridge.MatchValue("18", json.Number("18")))
}

// An explicitly empty protected_headers must survive a JSON round trip so
// a crit entry naming it still evaluates the same way at the RP.
func TestVerification_EmptyProtectedHeadersRoundTrip(t *testing.T) {
	entry := credbridge.CredentialEntry{
		Type:   []string{"vc"},
		Claims: map[string]any{"a": "b"},
		Verification: &credbridge.Verification{
			TrustStatus:      credbridge.TrustStatusValid,
			ProtectedHeaders: map[string]any{},
			Crit:             []string{"protected_headers"},
		},
	}
	require.NoError(t, credbridge.EvaluateCrit(entry), "before marshal")
	data, err := json.Marshal(entry)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"protected_headers":{}`)
	var decoded credbridge.CredentialEntry
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.NoError(t, credbridge.EvaluateCrit(decoded), "after round trip")
}

func newRP(t *testing.T, issuer string, client *http.Client, insecure bool) *credbridge.RP {
	t.Helper()
	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: issuer, ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: client, AllowInsecureHTTP: insecure,
	})
	require.NoError(t, err)
	return rp
}

func TestRP_Discover_RejectsHTTPIssuer(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	_, err := newRP(t, srv.URL, srv.Client(), false).Discover(t.Context())
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable)
	assert.Zero(t, hits.Load(), "no request may be sent to an http issuer")
}

func TestRP_Discover_PathIssuerAppendsSuffix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"issuer":"http://` + r.Host + `/tenant","authorization_endpoint":"a","token_endpoint":"t"}`))
	}))
	defer srv.Close()
	_, err := newRP(t, srv.URL+"/tenant/", srv.Client(), true).Discover(t.Context())
	// The issuer in the document has no trailing slash, the configured one does.
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable)
	assert.Equal(t, "/tenant/.well-known/openid-configuration", gotPath)

	_, err = newRP(t, srv.URL+"/tenant", srv.Client(), true).Discover(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "/tenant/.well-known/openid-configuration", gotPath)
}

func TestRP_Discover_BlocksHTTPSDowngradeRedirect(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plainHits.Add(1) }))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
	}))
	defer tlsSrv.Close()
	_, err := newRP(t, tlsSrv.URL, tlsSrv.Client(), false).Discover(t.Context())
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable)
	assert.Zero(t, plainHits.Load(), "redirect to http must not be followed")
}

// A stalled discovery fetch must not hold later callers past their deadline.
func TestRP_Discover_WaiterHonoursContext(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		_, _ = w.Write([]byte(`{"issuer":"http://` + r.Host + `","authorization_endpoint":"a","token_endpoint":"t"}`))
	}))
	defer srv.Close()
	defer close(release)
	rp := newRP(t, srv.URL, srv.Client(), true)

	go func() { _, _ = rp.Discover(context.Background()) }()
	<-started

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err := rp.Discover(ctx)
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable)
	assert.Less(t, time.Since(begin), 2*time.Second)
}

func TestOP_CloseIsIdempotentAndStopsStorage(t *testing.T) {
	for range 20 {
		op := mustOP(t)
		op.Close()
		op.Close()
	}
}
