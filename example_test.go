package credbridge_test

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/masv3971/credbridge"
	"github.com/masv3971/credbridge/internal/testsigner"
)

const exampleIssuer = "https://op.example.org"

// newExampleOP builds an OP configured with the credential presentations
// listed in scopes. It panics on setup failure — appropriate for godoc
// examples.
func newExampleOP(ctx context.Context, signer pki.Signer, scopes map[string]credbridge.OPCredentialTypeConfig, dcqlSupported bool) *credbridge.OP {
	op, err := credbridge.NewOP(ctx, credbridge.OPConfig{
		Issuer:                  exampleIssuer,
		AuthorizationEndpoint:   exampleIssuer + "/authorize",
		TokenEndpoint:           exampleIssuer + "/token",
		UserInfoEndpoint:        exampleIssuer + "/userinfo",
		JWKSURI:                 exampleIssuer + "/jwks.json",
		Signer:                  signer,
		CredentialPresentations: scopes,
		DCQLQuerySupported:      dcqlSupported,
		PairwiseSalt:            []byte("example-salt"),
	})
	if err != nil {
		panic(err)
	}
	return op
}

// ExampleNewOP shows the minimum wiring for a Provider bridge: publish
// discovery, start an authorization, hand the effective DCQL query to
// the wallet, and issue an ID Token.
func ExampleNewOP() {
	op := newExampleOP(context.Background(), testsigner.MustNew(), map[string]credbridge.OPCredentialTypeConfig{
		"ehic": {
			Format:       openid4vp.FormatSDJWTVC,
			Type:         []string{"urn:eu.europa.ec.eudi:ehic:1"},
			Claims:       [][]string{{"ehic_number"}, {"name"}, {"dob"}},
			SubjectClaim: []string{"ehic_number"},
		},
	}, false)
	defer op.Close()

	md := op.Metadata()
	fmt.Println("issuer:", md.Issuer)
	fmt.Println("dcql_supported:", md.DCQLQuerySupported)
	fmt.Println("ehic supported:", md.CredentialPresentationsSupported["ehic"].Format)

	// Output:
	// issuer: https://op.example.org
	// dcql_supported: false
	// ehic supported: dc+sd-jwt
}

// ExampleOP_scopeFlow drives the scope-based mode end-to-end using an
// SD-JWT VC fixture.
func ExampleOP_scopeFlow() {
	ctx := context.Background()
	signer := testsigner.MustNew()
	op := newExampleOP(ctx, signer, map[string]credbridge.OPCredentialTypeConfig{
		"ehic": {
			Format:       openid4vp.FormatSDJWTVC,
			Type:         []string{"urn:eu.europa.ec.eudi:ehic:1"},
			Claims:       [][]string{{"ehic_number"}, {"name"}},
			SubjectClaim: []string{"ehic_number"},
		},
	}, false)
	defer op.Close()

	opSession, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID:    "https://rp.example.org",
		RedirectURI: "https://rp.example.org/cb",
		Nonce:       "n-0S6_WzA2Mj",
		Scopes:      []string{"openid", "ehic"},
	})
	if err != nil {
		fmt.Println("start:", err)
		return
	}
	fmt.Println("wallet nonce equals OIDC nonce:", opSession.Nonce == "n-0S6_WzA2Mj")

	token := testsigner.MustIssueJWT(signer, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:ehic:1",
		"ehic_number": "1234567890",
		"name":        "John Doe",
	})
	result, err := op.HandleWalletResponse(ctx, opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"ehic": {token}},
		State:   opSession.State,
	}, nil)
	if err != nil {
		fmt.Println("handle:", err)
		return
	}
	tok, err := op.IssueIDToken(ctx, opSession, result, credbridge.OPTokenOptions{})
	if err != nil {
		fmt.Println("issue:", err)
		return
	}
	claims, err := testsigner.DecodeUnverified(tok)
	if err != nil {
		fmt.Println("decode:", err)
		return
	}
	sets, err := json.Marshal(claims[credbridge.PresentedCredentialSetsClaim])
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}
	fmt.Println("has presented_credential_sets:", len(sets) > 0)
	fmt.Println("first key:", firstCredentialKey(sets))

	// Output:
	// wallet nonce equals OIDC nonce: true
	// has presented_credential_sets: true
	// first key: ehic
}

// ExampleNewRP shows how a Relying Party primes discovery and
// constructs a scope-based authorization URL.
func ExampleNewRP() {
	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL:   exampleIssuer,
		ClientID:    "https://rp.example.org",
		RedirectURI: "https://rp.example.org/cb",
	})
	if err != nil {
		fmt.Println("new rp:", err)
		return
	}
	rp.PrimeDiscovery(&credbridge.RPDiscoveryMetadata{
		Issuer:                exampleIssuer,
		AuthorizationEndpoint: exampleIssuer + "/authorize",
		TokenEndpoint:         exampleIssuer + "/token",
		CredentialPresentationsSupported: map[string]credbridge.OPDiscoveryCredentialType{
			"ehic": {Format: openid4vp.FormatSDJWTVC, Type: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
		},
	})
	u, err := rp.BuildAuthorizationURL(context.Background(), credbridge.RPAuthorizationRequestOptions{
		Scopes: []string{"ehic"},
		Nonce:  "n-0S6_WzA2Mj",
		State:  "abc",
	})
	if err != nil {
		fmt.Println("build url:", err)
		return
	}
	fmt.Println("url ok:", u != "")

	// Output:
	// url ok: true
}

// ExampleRP_scopeFlow drives an end-to-end scope-based exchange: the
// OP (constructed here just to produce a realistic ID Token) issues a
// token; the RP parses and evaluates it.
func ExampleRP_scopeFlow() {
	ctx := context.Background()
	signer := testsigner.MustNew()
	op := newExampleOP(ctx, signer, map[string]credbridge.OPCredentialTypeConfig{
		"ehic": {
			Format:       openid4vp.FormatSDJWTVC,
			Type:         []string{"urn:eu.europa.ec.eudi:ehic:1"},
			Claims:       [][]string{{"ehic_number"}, {"name"}},
			SubjectClaim: []string{"ehic_number"},
		},
	}, false)
	defer op.Close()

	opSession, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID:    "https://rp.example.org",
		RedirectURI: "https://rp.example.org/cb",
		Nonce:       "n-0S6_WzA2Mj",
		Scopes:      []string{"openid", "ehic"},
	})
	if err != nil {
		fmt.Println("start:", err)
		return
	}
	token := testsigner.MustIssueJWT(signer, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:ehic:1",
		"ehic_number": "1234567890",
		"name":        "John Doe",
	})
	result, err := op.HandleWalletResponse(ctx, opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"ehic": {token}},
		State:   opSession.State,
	}, nil)
	if err != nil {
		fmt.Println("handle:", err)
		return
	}
	tok, err := op.IssueIDToken(ctx, opSession, result, credbridge.OPTokenOptions{})
	if err != nil {
		fmt.Println("issue:", err)
		return
	}

	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: exampleIssuer, ClientID: "https://rp.example.org", RedirectURI: "https://rp.example.org/cb",
	})
	if err != nil {
		fmt.Println("new rp:", err)
		return
	}
	claims, err := rp.ParseIDToken(ctx, tok, "n-0S6_WzA2Mj")
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	if err := claims.EvaluatePresentedCredentialSets(); err != nil {
		fmt.Println("evaluate:", err)
		return
	}
	entry, ok := claims.FirstEntry("", "ehic")
	if !ok {
		fmt.Println("no ehic")
		return
	}
	fmt.Println("sub not empty:", claims.Subject != "")
	fmt.Println("trust_status:", entry.Verification.TrustStatus)
	fmt.Println("ehic_number:", entry.Claims["ehic_number"])

	// Output:
	// sub not empty: true
	// trust_status: not_checked
	// ehic_number: 1234567890
}

// ExampleRP_dcqlFlow drives a DCQL-based request with a credential_sets
// alternation ("PID OR EHIC") and shows how the RP evaluates the
// returned claim, including the credential_set_id echo defined in RFC
// §5.1.1.
func ExampleRP_dcqlFlow() {
	ctx := context.Background()
	signer := testsigner.MustNew()
	op := newExampleOP(ctx, signer, map[string]credbridge.OPCredentialTypeConfig{
		"pid": {
			Format:       openid4vp.FormatSDJWTVC,
			Type:         []string{"urn:eu.europa.ec.eudi:pid:1"},
			SubjectClaim: []string{"family_name"},
		},
		"ehic": {
			Format:       openid4vp.FormatSDJWTVC,
			Type:         []string{"urn:eu.europa.ec.eudi:ehic:1"},
			SubjectClaim: []string{"ehic_number"},
		},
	}, true)
	defer op.Close()

	required := false
	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{
			{
				ID:     "pid",
				Format: openid4vp.FormatSDJWTVC,
				Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:pid:1"}},
				Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("family_name")}},
			},
			{
				ID:     "ehic",
				Format: openid4vp.FormatSDJWTVC,
				Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eu.europa.ec.eudi:ehic:1"}},
				Claims: []openid4vp.ClaimQuery{{Path: openid4vp.StringPath("ehic_number")}},
			},
		},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{Options: [][]string{{"pid"}, {"ehic"}}, Required: &required},
		},
	}
	opSession, err := op.StartAuthorization(ctx, credbridge.OPAuthorizationRequest{
		ClientID:         "https://rp.example.org",
		RedirectURI:      "https://rp.example.org/cb",
		Nonce:            "n-0S6_WzA2Mj",
		Scopes:           []string{"openid", "pid", "ehic"},
		DCQLQuery:        dcql,
		CredentialSetIDs: []string{"pid_or_ehic"},
	})
	if err != nil {
		fmt.Println("start:", err)
		return
	}

	token := testsigner.MustIssueJWT(signer, map[string]any{
		"vct":         "urn:eu.europa.ec.eudi:ehic:1",
		"ehic_number": "1234567890",
	})
	result, err := op.HandleWalletResponse(ctx, opSession, &openid4vp.VPResponse{
		VPToken: map[string][]string{"ehic": {token}},
		State:   opSession.State,
	}, nil)
	if err != nil {
		fmt.Println("handle:", err)
		return
	}
	tok, err := op.IssueIDToken(ctx, opSession, result, credbridge.OPTokenOptions{})
	if err != nil {
		fmt.Println("issue:", err)
		return
	}

	rp, err := credbridge.NewRP(credbridge.RPConfig{
		IssuerURL: exampleIssuer, ClientID: "https://rp.example.org", RedirectURI: "https://rp.example.org/cb",
	})
	if err != nil {
		fmt.Println("new rp:", err)
		return
	}
	claims, err := rp.ParseIDToken(ctx, tok, "n-0S6_WzA2Mj")
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	if err := claims.EvaluatePresentedCredentialSets(); err != nil {
		fmt.Println("evaluate:", err)
		return
	}
	set := claims.PresentedCredentialSets[0]
	fmt.Println("credential_set_id:", set.CredentialSetID)
	fmt.Println("has ehic:", len(set.Credentials["ehic"]) == 1)
	fmt.Println("has pid:", len(set.Credentials["pid"]) == 1)

	// Output:
	// credential_set_id: pid_or_ehic
	// has ehic: true
	// has pid: false
}

func firstCredentialKey(setsJSON []byte) string {
	var arr []struct {
		Credentials map[string]any `json:"credentials"`
	}
	if err := json.Unmarshal(setsJSON, &arr); err != nil || len(arr) == 0 {
		return ""
	}
	for k := range arr[0].Credentials {
		return k
	}
	return ""
}
