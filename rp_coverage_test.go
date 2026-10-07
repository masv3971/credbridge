package credbridge_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedClockRP builds an RP whose clock is pinned to now so ID Token
// exp/iat validation is deterministic.
func fixedClockRP(t *testing.T, now time.Time) *credbridge.RP {
	t.Helper()
	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL:   "https://op.example.org",
		ClientID:    "rp",
		RedirectURI: "https://rp.example.org/cb",
		Now:         func() time.Time { return now },
	})
	require.NoError(t, err, "NewRP")
	return rp
}

// §7.1: a well-formed ID Token with matching iss/aud/nonce and a valid
// exp/iat window must parse, and the presented_credential_sets claim
// must decode into the typed slice.
func TestRP_ParseIDToken_Valid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rp := fixedClockRP(t, now)
	sig := testsigner.MustNew()
	tok := testsigner.MustIssueJWT(sig, map[string]any{
		"iss":   "https://op.example.org",
		"sub":   "user-123",
		"aud":   []any{"other", "rp"},
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": "n",
		"presented_credential_sets": []any{
			map[string]any{
				"credential_set_id": "set1",
				"credentials": map[string]any{
					"ehic": []any{
						map[string]any{
							"type":   []any{"urn:eu.europa.ec.eudi:ehic:1"},
							"claims": map[string]any{"ehic_number": "1234567890"},
						},
					},
				},
			},
		},
	})
	claims, err := rp.ParseIDToken(t.Context(), tok, "n")
	require.NoError(t, err, "ParseIDToken")
	assert.Equal(t, "https://op.example.org", claims.Issuer)
	assert.Equal(t, "other", claims.Audience)
	assert.Equal(t, []string{"other", "rp"}, claims.Audiences)
	entry, ok := claims.FirstEntry("set1", "ehic")
	require.True(t, ok, "ehic entry missing")
	assert.Equal(t, "1234567890", entry.Claims["ehic_number"])
}

// §7.1: each standard-claim check in parseClaimsMap must reject a
// non-conforming ID Token.
func TestRP_ParseIDToken_StandardClaimErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sig := testsigner.MustNew()
	base := func() map[string]any {
		return map[string]any{
			"iss":   "https://op.example.org",
			"sub":   "user-123",
			"aud":   []any{"rp"},
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
			"nonce": "n",
		}
	}
	cases := []struct {
		name     string
		mutate   func(m map[string]any)
		nonceArg string
	}{
		{"iss mismatch", func(m map[string]any) { m["iss"] = "https://evil.example" }, "n"},
		{"aud mismatch", func(m map[string]any) { m["aud"] = []any{"someone-else"} }, "n"},
		{"iat missing", func(m map[string]any) { delete(m, "iat") }, "n"},
		{"exp missing", func(m map[string]any) { delete(m, "exp") }, "n"},
		{"expired", func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() }, "n"},
		{"iat in the future", func(m map[string]any) { m["iat"] = now.Add(time.Hour).Unix() }, "n"},
		{"empty expected nonce", func(m map[string]any) {}, ""},
		{"nonce mismatch", func(m map[string]any) { m["nonce"] = "other" }, "n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rp := fixedClockRP(t, now)
			claims := base()
			c.mutate(claims)
			tok := testsigner.MustIssueJWT(sig, claims)
			_, err := rp.ParseIDToken(t.Context(), tok, c.nonceArg)
			assert.ErrorIs(t, err, credbridge.ErrRPIDTokenInvalid)
		})
	}
}

// §5.1.1: a presented_credential_sets claim that is not a JSON array
// must be rejected with ErrRPUnexpectedResponseShape.
func TestRP_ParseIDToken_BadPresentedSetsShape(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rp := fixedClockRP(t, now)
	sig := testsigner.MustNew()
	tok := testsigner.MustIssueJWT(sig, map[string]any{
		"iss":                       "https://op.example.org",
		"sub":                       "user-123",
		"aud":                       "rp",
		"iat":                       now.Unix(),
		"exp":                       now.Add(time.Hour).Unix(),
		"nonce":                     "n",
		"presented_credential_sets": map[string]any{"not": "an array"},
	})
	_, err := rp.ParseIDToken(t.Context(), tok, "n")
	assert.ErrorIs(t, err, credbridge.ErrRPUnexpectedResponseShape)
}

// §4.2: EvaluatePresentedCredentialSets enforces presence, the §5.1.2
// entry shape, and crit satisfaction.
func TestRP_EvaluatePresentedCredentialSets(t *testing.T) {
	assert.ErrorIs(t, (*credbridge.RPClaims)(nil).EvaluatePresentedCredentialSets(),
		credbridge.ErrRPPresentedSetsMissing)
	empty := &credbridge.RPClaims{}
	assert.ErrorIs(t, empty.EvaluatePresentedCredentialSets(), credbridge.ErrRPPresentedSetsMissing)

	valid := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{{
		CredentialSetID: "set1",
		Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{Type: []string{"vc"}, Claims: map[string]any{"a": "b"}}},
		},
	}}}
	assert.NoError(t, valid.EvaluatePresentedCredentialSets())

	// Entry missing type.
	badType := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{{
		Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{Claims: map[string]any{"a": "b"}}},
		},
	}}}
	assert.ErrorIs(t, badType.EvaluatePresentedCredentialSets(), credbridge.ErrRPUnexpectedResponseShape)

	// Entry with neither claims nor namespaces.
	neither := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{{
		Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{Type: []string{"vc"}}},
		},
	}}}
	assert.ErrorIs(t, neither.EvaluatePresentedCredentialSets(), credbridge.ErrRPUnexpectedResponseShape)

	// Entry with both claims and namespaces.
	both := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{{
		Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{
				Type:       []string{"vc"},
				Claims:     map[string]any{"a": "b"},
				Namespaces: map[string]map[string]any{"ns": {"a": "b"}},
			}},
		},
	}}}
	assert.ErrorIs(t, both.EvaluatePresentedCredentialSets(), credbridge.ErrRPUnexpectedResponseShape)

	// Verification present without trust_status.
	noTrust := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{{
		Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{
				Type:         []string{"vc"},
				Claims:       map[string]any{"a": "b"},
				Verification: &credbridge.Verification{},
			}},
		},
	}}}
	assert.ErrorIs(t, noTrust.EvaluatePresentedCredentialSets(), credbridge.ErrRPUnexpectedResponseShape)

	// Unsatisfiable crit must surface.
	badCrit := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{{
		Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{
				Type:   []string{"vc"},
				Claims: map[string]any{"a": "b"},
				Verification: &credbridge.Verification{
					TrustStatus: credbridge.TrustStatusValid,
					Crit:        []string{"unknown_member"},
				},
			}},
		},
	}}}
	assert.ErrorIs(t, badCrit.EvaluatePresentedCredentialSets(), credbridge.ErrCritUnknownMember)
}

// Entries/FirstEntry cover the setKey wildcard, a specific-set filter,
// and the no-match path.
func TestRP_EntriesAndFirstEntry(t *testing.T) {
	assert.Nil(t, (*credbridge.RPClaims)(nil).Entries("", "ehic"))
	_, ok := (*credbridge.RPClaims)(nil).FirstEntry("", "ehic")
	assert.False(t, ok)

	claims := &credbridge.RPClaims{PresentedCredentialSets: credbridge.PresentedCredentialSets{
		{CredentialSetID: "a", Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{Type: []string{"vc"}, Claims: map[string]any{"n": "1"}}},
		}},
		{CredentialSetID: "b", Credentials: map[string][]credbridge.CredentialEntry{
			"ehic": {{Type: []string{"vc"}, Claims: map[string]any{"n": "2"}}},
		}},
	}}
	assert.Len(t, claims.Entries("", "ehic"), 2, "wildcard setKey matches both sets")
	assert.Len(t, claims.Entries("a", "ehic"), 1, "specific setKey filters")
	assert.Empty(t, claims.Entries("a", "pid"), "unknown credential key")

	entry, ok := claims.FirstEntry("b", "ehic")
	require.True(t, ok)
	assert.Equal(t, "2", entry.Claims["n"])
	_, ok = claims.FirstEntry("c", "ehic")
	assert.False(t, ok, "no matching set")
}

// BuildAuthorizationURL error and happy paths not exercised elsewhere.
func TestRP_BuildAuthorizationURL_Paths(t *testing.T) {
	prime := func(rp *credbridge.RP, dcql bool) {
		rp.PrimeDiscovery(&credbridge.RPDiscoveryMetadata{
			Issuer:                "https://op.example.org",
			AuthorizationEndpoint: "https://op.example.org/authorize?foo=bar",
			TokenEndpoint:         "https://op.example.org/token",
			DCQLQuerySupported:    dcql,
			CredentialPresentationsSupported: map[string]credbridge.OPDiscoveryCredentialType{
				"ehic": {Format: "dc+sd-jwt", Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			},
		})
	}

	// Happy path: existing base query is preserved and ExtraParams append.
	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: "https://op.example.org", ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
	})
	require.NoError(t, err, "NewRP")
	prime(rp, false)
	u, err := rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes:       []string{"ehic"},
		Nonce:        "n",
		State:        "st",
		ResponseType: "code",
		ExtraParams:  map[string][]string{"prompt": {"consent"}},
	})
	require.NoError(t, err, "BuildAuthorizationURL")
	assert.Contains(t, u, "foo=bar", "existing base query preserved")
	assert.Contains(t, u, "prompt=consent", "ExtraParams appended")
	assert.Contains(t, u, "state=st")

	// Reserved ExtraParams are rejected.
	_, err = rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes:      []string{"ehic"},
		Nonce:       "n",
		ExtraParams: map[string][]string{"scope": {"openid"}},
	})
	assert.Error(t, err, "reserved ExtraParams must be rejected")

	// Invalid redirect URI scheme is rejected.
	badRP, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: "https://op.example.org", ClientID: "rp", RedirectURI: "javascript:alert(1)",
	})
	require.NoError(t, err, "NewRP")
	prime(badRP, true)
	_, err = badRP.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes: []string{"ehic"}, Nonce: "n",
	})
	assert.Error(t, err, "invalid redirect scheme must be rejected")

	// credential_sets without an id each must be rejected before the wire.
	prime(rp, true)
	required := false
	_, err = rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes: []string{"ehic"},
		Nonce:  "n",
		DCQLQuery: &openid4vp.DCQL{
			Credentials: []openid4vp.CredentialQuery{{
				ID: "ehic", Format: openid4vp.FormatSDJWTVC,
				Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			}},
			CredentialSets: []openid4vp.CredentialSetQuery{{Options: [][]string{{"ehic"}}, Required: &required}},
		},
	})
	assert.Error(t, err, "missing credential_sets id must be rejected")

	// Duplicate credential_sets ids must be rejected.
	_, err = rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes: []string{"ehic"},
		Nonce:  "n",
		DCQLQuery: &openid4vp.DCQL{
			Credentials: []openid4vp.CredentialQuery{{
				ID: "ehic", Format: openid4vp.FormatSDJWTVC,
				Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			}},
			CredentialSets: []openid4vp.CredentialSetQuery{
				{Options: [][]string{{"ehic"}}, Required: &required},
				{Options: [][]string{{"ehic"}}, Required: &required},
			},
		},
		CredentialSetIDs: []string{"dup", "dup"},
	})
	assert.Error(t, err, "duplicate credential_sets ids must be rejected")

	// Discovery failure propagates.
	failRP, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: "https://op.unreachable.invalid", ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: &http.Client{Timeout: time.Millisecond},
	})
	require.NoError(t, err, "NewRP")
	_, err = failRP.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes: []string{"ehic"}, Nonce: "n",
	})
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable)
}

// Discover exercises the live HTTP path: the well-known transform, a
// non-200 status, an issuer mismatch, and the cached happy path.
func TestRP_Discover_HTTPPaths(t *testing.T) {
	// Non-200 status.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	rpDown, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: down.URL, ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: down.Client(),
	})
	require.NoError(t, err, "NewRP")
	_, err = rpDown.Discover(t.Context())
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable, "non-200 status")

	// Happy path: the handler must be reached at the well-known path and
	// echo back a matching issuer.
	var gotPath string
	okSrv := httptest.NewUnstartedServer(nil)
	okSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"issuer":"http://` + r.Host + `","authorization_endpoint":"a","token_endpoint":"t"}`))
	})
	okSrv.Start()
	defer okSrv.Close()
	rpOK, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: okSrv.URL, ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: okSrv.Client(),
	})
	require.NoError(t, err, "NewRP")
	md, err := rpOK.Discover(t.Context())
	require.NoError(t, err, "Discover")
	assert.Equal(t, "/.well-known/openid-configuration", gotPath)
	assert.Equal(t, okSrv.URL, md.Issuer)
	// Second call is served from cache.
	_, err = rpOK.Discover(t.Context())
	require.NoError(t, err, "cached Discover")

	// Issuer mismatch.
	mismatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://someone-else.example","authorization_endpoint":"a","token_endpoint":"t"}`))
	}))
	defer mismatch.Close()
	rpMismatch, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: mismatch.URL, ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: mismatch.Client(),
	})
	require.NoError(t, err, "NewRP")
	_, err = rpMismatch.Discover(t.Context())
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable, "issuer mismatch")
}
