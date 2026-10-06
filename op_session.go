package credbridge

import "github.com/SUNET/vc/pkg/openid4vp"

// OPSession is the per-authentication state the OP threads through the
// bridge flow. The caller may treat it as opaque outside tests.
type OPSession struct {
	// ID is a random identifier chosen by the OP. It is used to look the
	// session up from the OPStorage between StartAuthorization and
	// IssueIDToken.
	ID string

	// ClientID, RedirectURI, State, Nonce, RequestedScopes are copied
	// from the incoming OIDC authorization request.
	ClientID        string
	RedirectURI     string
	State           string
	Nonce           string
	RequestedScopes []string

	// DCQL is the DCQL query the OP will send to the wallet.
	// In scope-based mode it is derived from RequestedScopes; in
	// DCQL-based mode it is the RP query with any uncovered scopes
	// augmented per Appendix A.2.
	DCQL ResolvedDCQL

	// RPDCQLQuerySupplied is true when the RP sent a dcql_query member.
	RPDCQLQuerySupplied bool

	// CreatedAt records when the session was started.
	CreatedAt int64
}

// ResolvedDCQL is a JSON-serialisable view of the DCQL query the OP has
// committed to for the current session: scope-based translations,
// Appendix A.2 augmentation, and RP-supplied constraints have all been
// applied. Response processing consults it to filter, match, and
// validate the wallet's presentation.
type ResolvedDCQL struct {
	Credentials    []ResolvedCredentialQuery
	CredentialSets []ResolvedCredentialSet
}

// ResolvedCredentialQuery mirrors openid4vp.CredentialQuery with only the
// fields credbridge needs to reason about at response time.
type ResolvedCredentialQuery struct {
	ID     string
	Scope  string // scope value if this query was derived from a scope, else ""
	Format string
	Type   []string
	// Claims is the set of DCQL claim entries the RP asked for. Empty
	// means "all pre-registered claims" (scope-based mode or omitted
	// DCQL claims member).
	Claims []ResolvedClaim
	// TrustedAuthorities is the RP's trusted_authorities constraint after
	// the OP's SSRF allowlist has been applied (Section 7.4). Response
	// validation enforces it against each presented credential.
	TrustedAuthorities []openid4vp.TrustedAuthority
	// TrustedAuthorityAllowed reports whether the OP's SSRF allowlist
	// admitted at least one of the trusted_authorities entries.
	TrustedAuthorityAllowed bool
	// RequireCryptographicHolderBinding carries the RP's effective
	// require_cryptographic_holder_binding constraint (OpenID4VP §6.1,
	// default true) so response validation can enforce holder binding.
	RequireCryptographicHolderBinding bool
	// ClaimSets is the DCQL "claim_sets" alternation, if any. Each
	// inner array lists claim IDs (matching ResolvedClaim.ID).
	ClaimSets [][]string
}

// ResolvedClaim mirrors an openid4vp.ClaimQuery entry the RP sent.
type ResolvedClaim struct {
	ID     string
	Path   []string
	Values []any
}

// ResolvedCredentialSet mirrors openid4vp.CredentialSetQuery plus the
// RFC §4.1.2 REQUIRED "id".
type ResolvedCredentialSet struct {
	ID       string
	Options  [][]string
	Required bool
}
