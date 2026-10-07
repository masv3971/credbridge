# credbridge

Go implementation of
[`draft-svensson-credential-oidc-bridge`](https://github.com/masv3971/rfc_credential_oidc_bridge/blob/main/draft-svensson-credential-oidc-bridge.txt) —
a mechanism for conveying digital credential claims through OpenID
Connect by way of an OpenID Provider that acts as a bridge to a
credential wallet.

The library exposes two roles under a single import path:

- **OP** — the Provider bridge. Publishes discovery metadata, translates
  an RP's OIDC request into a wallet presentation request (via
  OpenID4VP), verifies the wallet response, and issues ID Tokens /
  UserInfo payloads that carry the `presented_credential_sets` claim
  defined in RFC §5.1.
- **RP** — the Relying Party client. Discovers the OP, builds the
  authorization URL (scope-based or DCQL-based), parses the returned
  ID Token or UserInfo response, and evaluates the
  `presented_credential_sets` claim per RFC §4.2.

Wire types shared by both roles (`PresentedCredentialSet`,
`CredentialEntry`, `Verification`, `Digest`, `TrustStatus`,
`HolderBinding`) have no prefix. Role-specific configuration, request,
and error types carry an `OP` or `RP` prefix so IDE completion shows
only role-appropriate members on `*OP` / `*RP`.

## Requirements

- Go 1.26 or later.
- Depends on [`github.com/SUNET/vc`](https://github.com/SUNET/vc)
  (`pkg/openid4vp`, `pkg/jose`, `pkg/oauth2`, `pkg/pki`) as the
  underlying OpenID4VP + JOSE + OAuth 2.0 toolkit.

## Install

```
go get github.com/masv3971/credbridge
```

## OP quickstart

```go
import (
    "context"

    "github.com/SUNET/vc/pkg/openid4vp"
    "github.com/masv3971/credbridge"
)

op, err := credbridge.NewOP(ctx, credbridge.OPConfig{
    Issuer:                "https://op.example.org",
    AuthorizationEndpoint: "https://op.example.org/authorize",
    TokenEndpoint:         "https://op.example.org/token",
    Signer:                mySigner, // pki.Signer
    CredentialPresentations: map[string]credbridge.OPCredentialTypeConfig{
        "ehic": {
            Format:       openid4vp.FormatSDJWTVC,
            Type:         []string{"urn:eu.europa.ec.eudi:ehic:1"},
            SubjectClaim: []string{"ehic_number"},
        },
    },
    PairwiseSalt: []byte("random-per-deployment"),
})
defer op.Close()

// 1. Publish discovery metadata:  op.Metadata()
// 2. On /authorize:                op.StartAuthorization(ctx, req)
// 3. Build the wallet request:     op.BuildWalletRequest(ctx, sess, responseURI)
// 4. On wallet callback:           op.HandleWalletResponse(ctx, sess, resp, matcher)
// 5. Issue the ID Token:           op.IssueIDToken(ctx, sess, result, opts)
// 6. Or produce UserInfo:          op.UserInfoPayload(sess, result)
```

## RP quickstart

```go
rp, err := credbridge.NewRP(credbridge.RPConfig{
    IssuerURL:   "https://op.example.org",
    ClientID:    "https://rp.example.org",
    RedirectURI: "https://rp.example.org/cb",
})

url, err := rp.BuildAuthorizationURL(ctx, credbridge.RPAuthorizationRequestOptions{
    Scopes: []string{"ehic"},
    Nonce:  freshNonce,
    State:  freshState,
})

claims, err := rp.ParseIDToken(ctx, idToken, freshNonce)
if err := claims.EvaluatePresentedCredentialSets(); err != nil {
    // §4.2 check failed (crit unsatisfied, essential claim absent, ...)
}
entry, ok := claims.FirstEntry("", "ehic")
```

See [`example_test.go`](example_test.go) for runnable end-to-end
examples covering scope-based and DCQL-based flows, and see
[`doc.go`](doc.go) for the full API tour.

## Credential Set ids

RFC §4.1.2 makes the `id` on a DCQL `credential_sets` entry REQUIRED,
but the upstream `openid4vp.CredentialSetQuery` type does not model
it. `credbridge` bridges that gap: callers pass the ids alongside the
DCQL query via `OPAuthorizationRequest.CredentialSetIDs` and
`RPAuthorizationRequestOptions.CredentialSetIDs`. On the RP side the
ids are spliced into the marshalled DCQL query so the wire form
matches the RFC; on the OP side the ids are validated for uniqueness
and DCQL charset conformance and later echoed back as
`credential_set_id` on each satisfied Credential Set.

## Build, test, lint

```
make test        # go test -count=1 ./...
make lint        # staticcheck + govulncheck + gosec + deadcode
make fmt         # gofumpt -w .
make tidy        # go mod tidy
make vscode      # install the tools above
```

## License

BSD-2-Clause. See [`LICENSE`](LICENSE).
