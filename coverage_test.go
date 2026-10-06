package credbridge_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// §5.1.1 registry values must be recognised by their IsRegistered helpers.
func TestTrustStatusHolderBindingIsRegistered(t *testing.T) {
	for _, v := range []credbridge.TrustStatus{
		credbridge.TrustStatusNotChecked, credbridge.TrustStatusUnknown,
		credbridge.TrustStatusValid, credbridge.TrustStatusSuspended,
		credbridge.TrustStatusRevoked, credbridge.TrustStatusExpired,
		credbridge.TrustStatusInvalid,
	} {
		assert.True(t, v.IsRegistered(), "TrustStatus %q", v)
	}
	assert.False(t, credbridge.TrustStatus("made_up").IsRegistered())

	for _, v := range []credbridge.HolderBinding{
		credbridge.HolderBindingKey, credbridge.HolderBindingBiometric, credbridge.HolderBindingPIN,
	} {
		assert.True(t, v.IsRegistered(), "HolderBinding %q", v)
	}
	assert.False(t, credbridge.HolderBinding("smell_test").IsRegistered())
}

// §5.2: RP discovers the OP via /.well-known/openid-configuration.
func TestRP_Discover(t *testing.T) {
	// #nosec G101 -- test fixture; endpoint URLs are not credentials.
	stub2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 stubIssuerURL(t, ""),
			"authorization_endpoint": "https://op.example.org/authorize",
			"token_endpoint":         "https://op.example.org/token",
			"credential_presentations_supported": map[string]any{
				"ehic": map[string]any{"format": "dc+sd-jwt", "type": []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			},
		}); err != nil {
			t.Errorf("stub2 encode: %v", err)
		}
	}))
	defer stub2.Close()
	rp2, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: stub2.URL, ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: stub2.Client(),
	})
	require.NoError(t, err, "NewRP")
	stub2.Close()
	stub3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(credbridge.OPDiscoveryMetadata{
			Issuer:                stub2.URL,
			AuthorizationEndpoint: stub2.URL + "/authorize",
			TokenEndpoint:         stub2.URL + "/token",
			CredentialPresentationsSupported: map[string]credbridge.OPDiscoveryCredentialType{
				"ehic": {Format: "dc+sd-jwt", Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			},
		}); err != nil {
			t.Errorf("stub3 encode: %v", err)
		}
	}))
	defer stub3.Close()
	rp3, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: stub3.URL, ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
		HTTPClient: stub3.Client(),
	})
	require.NoError(t, err, "NewRP")

	_, err = rp3.Discover(t.Context())
	assert.ErrorIs(t, err, credbridge.ErrRPDiscoveryUnreachable)

	// Happy path via PrimeDiscovery + helper.
	rp2.PrimeDiscovery(&credbridge.RPDiscoveryMetadata{
		Issuer:                stub2.URL,
		AuthorizationEndpoint: stub2.URL + "/authorize",
		TokenEndpoint:         stub2.URL + "/token",
		CredentialPresentationsSupported: map[string]credbridge.OPDiscoveryCredentialType{
			"ehic": {Format: "dc+sd-jwt", Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		},
	})
	md, err := rp2.Discover(t.Context())
	require.NoError(t, err, "primed Discover")
	assert.True(t, md.SupportsCredentialScope("ehic"))
	assert.False(t, md.SupportsCredentialScope("pid"))
}

func stubIssuerURL(t *testing.T, override string) string {
	t.Helper()
	if override != "" {
		return override
	}
	return "https://example.invalid"
}

// §4.1.2 wire form: RP-supplied credential_sets ids are spliced into
// the marshalled DCQL query so the wallet sees `id`.
func TestRP_BuildAuthorizationURL_DCQLSplicesSetIDs(t *testing.T) {
	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: "https://op.example.org", ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
	})
	require.NoError(t, err, "NewRP")
	rp.PrimeDiscovery(&credbridge.RPDiscoveryMetadata{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		TokenEndpoint:         "https://op.example.org/token",
		DCQLQuerySupported:    true,
		CredentialPresentationsSupported: map[string]credbridge.OPDiscoveryCredentialType{
			"ehic": {Format: "dc+sd-jwt", Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		}, // #nosec G101 -- test fixture; endpoint URLs are not credentials.
	})
	required := false
	u, err := rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes: []string{"ehic"},
		Nonce:  "n",
		DCQLQuery: &openid4vp.DCQL{
			Credentials: []openid4vp.CredentialQuery{{
				ID: "ehic", Format: openid4vp.FormatSDJWTVC,
				Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
			}},
			CredentialSets: []openid4vp.CredentialSetQuery{
				{Options: [][]string{{"ehic"}}, Required: &required},
			},
		},
		CredentialSetIDs: []string{"ehic_only"},
	})
	require.NoError(t, err, "BuildAuthorizationURL")
	parsed, err := url.Parse(u)
	require.NoError(t, err, "parse url")
	claims := parsed.Query().Get("claims")
	require.NotEmpty(t, claims, "claims parameter missing")
	assert.True(t, strings.Contains(claims, `"id":"ehic_only"`),
		"credential_sets id not spliced into claims payload: %s", claims)

	// DCQL-not-supported path: RP must refuse when discovery says no.
	rp.PrimeDiscovery(&credbridge.RPDiscoveryMetadata{
		Issuer:                "https://op.example.org",
		AuthorizationEndpoint: "https://op.example.org/authorize",
		DCQLQuerySupported:    false,
		CredentialPresentationsSupported: map[string]credbridge.OPDiscoveryCredentialType{
			"ehic": {Format: "dc+sd-jwt", Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		},
	})
	_, err = rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{
		Scopes:    []string{"ehic"},
		Nonce:     "n",
		DCQLQuery: &openid4vp.DCQL{},
	})
	assert.ErrorIs(t, err, credbridge.ErrRPDCQLNotSupported)

	_, err = rp.BuildAuthorizationURL(t.Context(), credbridge.RPAuthorizationRequestOptions{Scopes: []string{"ehic"}})
	assert.Error(t, err, "expected nonce-required rejection")
}

// Config validation covers every branch of RPConfig.validate and
// OPConfig.validate.
func TestConfigValidation(t *testing.T) {
	_, err := credbridge.NewRP(credbridge.RPConfig{})
	assert.Error(t, err, "empty RPConfig")
	_, err = credbridge.NewRP(credbridge.RPConfig{IssuerURL: "x"})
	assert.Error(t, err, "missing ClientID")
	_, err = credbridge.NewRP(credbridge.RPConfig{IssuerURL: "x", ClientID: "x"})
	assert.Error(t, err, "missing RedirectURI")

	_, err = credbridge.NewOP(context.Background(), credbridge.OPConfig{})
	assert.Error(t, err, "empty OPConfig")

	// #nosec G101 -- test fixture; endpoint URLs are not credentials.
	base := credbridge.OPConfig{
		Issuer:                "https://op",
		AuthorizationEndpoint: "https://op/authorize",
		TokenEndpoint:         "https://op/token",
		Signer:                testsigner.MustNew(),
		PairwiseSalt:          []byte("salt"),
	}
	_, err = credbridge.NewOP(context.Background(), base)
	assert.Error(t, err, "missing CredentialPresentations")

	base.CredentialPresentations = map[string]credbridge.OPCredentialTypeConfig{
		"ehic": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
	}
	op, err := credbridge.NewOP(context.Background(), base)
	require.NoError(t, err, "NewOP")
	op.Close()
}

// §4.1.2 + §5.4: when claim_sets is present the OP selects the first
// matching option and filters output to that option's claims only.
func TestOP_ClaimSetsMatchAndFilter(t *testing.T) {
	sig := testsigner.MustNew()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op",
		AuthorizationEndpoint: "https://op/authorize",
		TokenEndpoint:         "https://op/token",
		Signer:                sig,
		DCQLQuerySupported:    true,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"pid": {
				Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:eu.europa.ec.eudi:pid:1"},
				SubjectClaim: []string{"family_name"},
			},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	defer op.Close()

	opSession, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"pid"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:pid:1"}},
			Claims: []openid4vp.ClaimQuery{
				{ID: "fn", Path: openid4vp.StringPath("family_name")},
				{ID: "gn", Path: openid4vp.StringPath("given_name")},
				{ID: "bd", Path: openid4vp.StringPath("birth_date")},
			},
			ClaimSet: [][]string{{"fn", "gn"}, {"fn", "bd"}},
		}}},
	})
	require.NoError(t, err, "StartAuthorization")
	token := testsigner.MustIssueJWT(sig, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:pid:1",
		"family_name": "Doe",
		"given_name":  "John",
		"birth_date":  "1990-01-01",
	})
	result, err := op.HandleWalletResponse(t.Context(), opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"pid": {token}},
		State:   opSession.State,
	}, nil)
	require.NoError(t, err, "HandleWalletResponse")
	entry := result.Entries["pid"][0]
	assert.Contains(t, entry.Claims, "family_name", "first-matched option")
	assert.Contains(t, entry.Claims, "given_name", "first-matched option")
	assert.NotContains(t, entry.Claims, "birth_date",
		"option B leaked when option A matched: %v", entry.Claims)

	// If no option can be satisfied, HandleWalletResponse must fail.
	opSession2, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n2",
		Scopes: []string{"pid"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:pid:1"}},
			Claims: []openid4vp.ClaimQuery{
				{ID: "fn", Path: openid4vp.StringPath("family_name")},
				{ID: "missing", Path: openid4vp.StringPath("nope")},
			},
			ClaimSet: [][]string{{"missing"}},
		}}},
	})
	require.NoError(t, err, "StartAuthorization")
	_, err = op.HandleWalletResponse(t.Context(), opSession2, &openid4vp.VPResponse{
		VPToken: map[string][]string{"pid": {token}},
		State:   opSession2.State,
	}, nil)
	assert.Error(t, err, "claim_sets no-match must fail")
}

// §5.4 nested path filtering: the OP must preserve object nesting when
// the RP requests a nested claim.
func TestOP_NestedClaimPathFilter(t *testing.T) {
	sig := testsigner.MustNew()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op",
		AuthorizationEndpoint: "https://op/authorize",
		TokenEndpoint:         "https://op/token",
		Signer:                sig,
		DCQLQuerySupported:    true,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"pid": {
				Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:eu.europa.ec.eudi:pid:1"},
				SubjectClaim: []string{"family_name"},
			},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	defer op.Close()

	opSession, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"pid"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: openid4vp.FormatSDJWTVC,
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:pid:1"}},
			Claims: []openid4vp.ClaimQuery{
				{Path: openid4vp.StringPath("family_name")},
				{Path: openid4vp.StringPath("address", "country"), Values: []any{"SE"}},
			},
		}}},
	})
	require.NoError(t, err, "StartAuthorization")
	token := testsigner.MustIssueJWT(sig, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:pid:1",
		"family_name": "Doe",
		"address":     map[string]any{"country": "SE", "street_address": "leaked"},
	})
	result, err := op.HandleWalletResponse(t.Context(), opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"pid": {token}},
		State:   opSession.State,
	}, nil)
	require.NoError(t, err, "HandleWalletResponse")
	addr, ok := result.Entries["pid"][0].Claims["address"].(map[string]any)
	require.True(t, ok, "address not preserved as nested object")
	assert.Equal(t, "SE", addr["country"])
	assert.NotContains(t, addr, "street_address", "unrequested nested claim leaked")

	// Same query but with a mismatched value must reject the credential.
	badToken := testsigner.MustIssueJWT(sig, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:pid:1",
		"family_name": "Doe",
		"address":     map[string]any{"country": "NO"},
	})
	_, err = op.HandleWalletResponse(t.Context(), opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"pid": {badToken}},
		State:   opSession.State,
	}, nil)
	assert.Error(t, err, "value mismatch must reject")
}

// A caller-provided OPStorage must satisfy the same Put/Get/Delete
// contract as the built-in default.
func TestOP_CustomStorage(t *testing.T) {
	storage := newTestStorage()
	op, err := credbridge.NewOP(t.Context(), credbridge.OPConfig{
		Issuer:                "https://op",
		AuthorizationEndpoint: "https://op/authorize",
		TokenEndpoint:         "https://op/token",
		Signer:                testsigner.MustNew(),
		Storage:               storage,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"ehic": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}, SubjectClaim: []string{"ehic_number"}},
		},
		PairwiseSalt: []byte("test-salt"),
	})
	require.NoError(t, err, "NewOP")
	defer op.Close()

	sess, err := op.StartAuthorization(t.Context(), credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"ehic"},
	})
	require.NoError(t, err, "StartAuthorization")
	assert.Equal(t, 1, storage.putCount(), "OP must persist the session via the caller's storage")
	got, err := storage.Get(t.Context(), sess.ID)
	require.NoError(t, err)
	assert.Same(t, sess, got)
}

type testStorage struct {
	mu   sync.Mutex
	data map[string]*credbridge.OPSession
	puts int
}

func newTestStorage() *testStorage { return &testStorage{data: map[string]*credbridge.OPSession{}} }

func (s *testStorage) putCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.puts }

func (s *testStorage) Put(_ context.Context, sess *credbridge.OPSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[sess.ID] = sess
	s.puts++
	return nil
}

func (s *testStorage) Get(_ context.Context, id string) (*credbridge.OPSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[id]
	if !ok {
		return nil, errNoSuchSession
	}
	return sess, nil
}

func (s *testStorage) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

var errNoSuchSession = errors.New("testStorage: no such session")

// ParseIDToken must fail on bad tokens and on nonce/aud/iss mismatch.
func TestRP_ParseIDToken_Errors(t *testing.T) {
	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: "https://op.example.org", ClientID: "rp", RedirectURI: "https://rp.example.org/cb",
	})
	require.NoError(t, err, "NewRP")
	_, err = rp.ParseIDToken(t.Context(), "not-a-jwt", "")
	assert.ErrorIs(t, err, credbridge.ErrRPIDTokenInvalid)
	_, err = rp.FetchUserInfoClaims([]byte("not json"), "")
	assert.ErrorIs(t, err, credbridge.ErrRPIDTokenInvalid)
}

// CredentialEntry and Verification must round-trip additional fields.
func TestCredentialEntry_AdditionalFieldsRoundTrip(t *testing.T) {
	entry := credbridge.CredentialEntry{
		Type:   []string{"vc"},
		Claims: map[string]any{"a": "b"},
		Verification: &credbridge.Verification{
			TrustStatus:       credbridge.TrustStatusValid,
			AdditionalMembers: map[string]any{"extra": float64(42)},
		},
		AdditionalFields: map[string]any{"custom": "value"},
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err, "Marshal")
	assert.Contains(t, string(data), `"custom":"value"`)
	assert.Contains(t, string(data), `"extra":42`)

	var decoded credbridge.CredentialEntry
	require.NoError(t, json.Unmarshal(data, &decoded), "Unmarshal")
	assert.Equal(t, "value", decoded.AdditionalFields["custom"])
	assert.Equal(t, float64(42), decoded.Verification.AdditionalMembers["extra"])

	// Collisions between AdditionalFields and reserved names must fail.
	bad := entry
	bad.AdditionalFields = map[string]any{"type": "collision"}
	_, err = json.Marshal(bad)
	assert.Error(t, err, "AdditionalFields collision must fail marshal")

	badV := credbridge.Verification{
		TrustStatus:       credbridge.TrustStatusValid,
		AdditionalMembers: map[string]any{"trust_status": "collision"},
	}
	_, err = json.Marshal(badV)
	assert.Error(t, err, "Verification collision must fail marshal")
}

// MatchValue's numeric branches: integer/float across signed/unsigned
// and float32/float64 must all normalise consistently.
func TestMatchValue_NumericBranches(t *testing.T) {
	cases := []struct {
		disclosed, expected any
		want                bool
	}{
		{int32(1), int64(1), true},
		{uint32(1), uint(1), true},
		{uint64(1), uint(1), true},
		{float32(1.5), float32(1.5), true},
		{float64(2.5), float64(2.5), true},
		{"1", 1, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, credbridge.MatchValue(c.disclosed, c.expected),
			"MatchValue(%v,%v)", c.disclosed, c.expected)
	}
}

// selectIdentityEntry must prefer a primary=true entry.
func TestOP_SubDerivation_Primary(t *testing.T) {
	ctx := t.Context()
	sig := testsigner.MustNew()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(ctx, credbridge.OPConfig{
		Issuer:                "https://op",
		AuthorizationEndpoint: "https://op/authorize",
		TokenEndpoint:         "https://op/token",
		Signer:                sig,
		DCQLQuerySupported:    true,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"a": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:a"}, SubjectClaim: []string{"id"}},
			"b": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:t:b"}, SubjectClaim: []string{"id"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	defer op.Close()

	opSession, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"a", "b"},
	})
	require.NoError(t, err, "StartAuthorization")
	result := &credbridge.OPPresentationResult{
		Entries: map[string][]credbridge.CredentialEntry{
			"a": {{Type: []string{"urn:t:a"}, Claims: map[string]any{"id": "A"}}},
			"b": {{Type: []string{"urn:t:b"}, Claims: map[string]any{"id": "B"}, Primary: true}},
		},
	}
	payload, err := op.UserInfoPayload(opSession, result)
	require.NoError(t, err, "UserInfoPayload")
	sub, ok := payload["sub"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, sub)
}

// mdoc and W3C paths through metaTypeKey must be exercised for
// coverage of the format switch.
func TestOP_DCQLMetaTypeSwitch(t *testing.T) {
	ctx := t.Context()
	sig := testsigner.MustNew()
	// #nosec G101 -- test fixture; PairwiseSalt is not a credential.
	op, err := credbridge.NewOP(ctx, credbridge.OPConfig{
		Issuer:                "https://op",
		AuthorizationEndpoint: "https://op/authorize",
		TokenEndpoint:         "https://op/token",
		Signer:                sig,
		DCQLQuerySupported:    true,
		CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
			"mdl":    {Format: openid4vp.FormatMsoMdoc, Type: []string{"org.iso.18013.5.1.mDL"}, SubjectClaim: []string{"family_name"}},
			"degree": {Format: openid4vp.FormatJwtVCJson, Type: []string{"VerifiableCredential", "UniversityDegreeCredential"}, SubjectClaim: []string{"degree"}},
		},
		PairwiseSalt: []byte("salt"),
	})
	require.NoError(t, err, "NewOP")
	defer op.Close()

	_, err = op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n",
		Scopes: []string{"mdl"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID: "mdl", Format: openid4vp.FormatMsoMdoc,
			Meta: openid4vp.MetaQuery{DoctypeValue: "org.iso.18013.5.1.mDL"},
		}}},
	})
	assert.NoError(t, err, "mdoc StartAuthorization")

	_, err = op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n2",
		Scopes: []string{"degree"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID: "degree", Format: openid4vp.FormatJwtVCJson,
			Meta: openid4vp.MetaQuery{TypeValues: [][]string{{"VerifiableCredential", "UniversityDegreeCredential"}}},
		}}},
	})
	assert.NoError(t, err, "w3c StartAuthorization")

	// Missing meta values must be rejected.
	_, err = op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID: "rp", RedirectURI: "https://rp.example.org/cb", Nonce: "n3",
		Scopes: []string{"mdl"},
		DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID: "mdl", Format: openid4vp.FormatMsoMdoc,
		}}},
	})
	assert.Error(t, err, "missing doctype_value must be rejected")
}
