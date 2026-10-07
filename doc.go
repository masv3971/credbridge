// Package credbridge implements draft-svensson-credential-oidc-bridge: a
// mechanism for conveying digital credential claims through OpenID Connect
// by way of an OpenID Provider that acts as a bridge to a credential
// wallet.
//
// The package exposes two roles under a single import path. Callers pick
// one role by using the matching constructor and interact only with the
// returned value's method set:
//
//   - [NewOP] returns an [*OP]. Use it to implement the OpenID Provider
//     bridge: publish discovery metadata, translate an RP's OIDC request
//     into a wallet presentation request, verify the wallet's response,
//     and issue ID Tokens or UserInfo payloads containing the
//     "presented_credential_sets" claim.
//
//   - [NewRP] returns an [*RP]. Use it to implement the Relying Party:
//     discover the OP, build the OIDC authorization URL (optionally with a
//     DCQL query), parse the returned ID Token or UserInfo response, and
//     evaluate the "presented_credential_sets" claim per Section 4.2 of the
//     draft.
//
// Symbols are named to make the role obvious:
//
//   - Types and errors specific to one role carry an OP or RP prefix
//     (for example [OPConfig], [OPAuthorizationRequest], [RPConfig],
//     [RPAuthorizationRequestOptions], [ErrOPInvalidRequest],
//     [ErrRPDCQLNotSupported]).
//
//   - Wire types that are shared by both roles carry no prefix
//     ([PresentedCredentialSet], [CredentialEntry], [Verification],
//     [TrustStatus], [HolderBinding], [Digest]).
//
// The wallet-facing presentation protocol used by the OP is OpenID for
// Verifiable Presentations (OpenID4VP). The DIDComm binding sketched in
// Appendix B of the draft is intentionally not implemented.
package credbridge
