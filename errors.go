package credbridge

import "errors"

// OP-side errors. These map to OIDC/OAuth error codes as noted.
var (
	// ErrOPInvalidRequest maps to the OIDC "invalid_request" error code
	// (Sections 4.1.2, 5.3, 7.4).
	ErrOPInvalidRequest = errors.New("credbridge/op: invalid_request")

	// ErrOPAccessDenied maps to the OIDC "access_denied" error code
	// (Sections 5.5, 6.2, Appendix A.4).
	ErrOPAccessDenied = errors.New("credbridge/op: access_denied")

	// ErrOPTrustedAuthorityDisallowed signals a "trusted_authorities"
	// entry that was rejected by the OP's SSRF allowlist (Section 7.4).
	ErrOPTrustedAuthorityDisallowed = errors.New("credbridge/op: trusted authority off allowlist")

	// ErrOPBridgePrefixReserved signals an RP-supplied DCQL Credential
	// Query "id" that begins with the reserved prefix (Appendix A.2).
	ErrOPBridgePrefixReserved = errors.New("credbridge/op: DCQL id begins with reserved prefix")

	// ErrOPMDocDualBody signals a Credential Entry that carries both
	// "claims" and "namespaces", forbidden by Section 5.1.2.
	ErrOPMDocDualBody = errors.New("credbridge/op: credential entry has both claims and namespaces")

	// ErrOPUnsupportedScope signals that none of the requested credential
	// scopes are present in the OP's credential_presentations_supported
	// metadata (Section 5.3, step 1).
	ErrOPUnsupportedScope = errors.New("credbridge/op: no supported credential scope in request")

	// ErrOPWalletTimeout signals that the wallet did not respond in time
	// (Section 6.2).
	ErrOPWalletTimeout = errors.New("credbridge/op: wallet did not respond in time")
)

// RP-side errors.
var (
	// ErrRPDCQLNotSupported signals that the RP tried to include a
	// dcql_query while the OP's discovery metadata reported
	// dcql_query_supported=false (Sections 4.1, 5.2).
	ErrRPDCQLNotSupported = errors.New("credbridge/rp: OP does not support dcql_query")

	// ErrRPPresentedSetsMissing signals that an essential
	// presented_credential_sets claim was absent from the ID Token or
	// UserInfo response (Section 4.2).
	ErrRPPresentedSetsMissing = errors.New("credbridge/rp: presented_credential_sets claim missing")

	// ErrRPIDTokenInvalid signals a token that failed signature or
	// standard-claim validation (Section 7.1).
	ErrRPIDTokenInvalid = errors.New("credbridge/rp: id token invalid")

	// ErrRPDiscoveryUnreachable signals that the OP discovery document
	// could not be fetched or parsed (Section 5.2).
	ErrRPDiscoveryUnreachable = errors.New("credbridge/rp: discovery document unreachable")

	// ErrRPUnexpectedResponseShape signals that the presented_credential_sets
	// value in the token was not the JSON array shape defined in Section
	// 5.1.1.
	ErrRPUnexpectedResponseShape = errors.New("credbridge/rp: presented_credential_sets is not a JSON array")
)
