package credbridge

import (
	"context"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// CredentialVerifier verifies one presented credential (§5.3 step 4).
// It checks the issuer signature, that the credential chains to one of
// Query.TrustedAuthorities, and, when Query.RequireCryptographicHolderBinding
// is set, a holder-binding proof bound to Nonce and ClientID (§7.1).
// A returned error means the credential failed verification.
type CredentialVerifier interface {
	VerifyCredential(ctx context.Context, req CredentialVerificationRequest) (*CredentialVerification, error)
}

// CredentialVerifierFunc adapts a function to CredentialVerifier.
type CredentialVerifierFunc func(ctx context.Context, req CredentialVerificationRequest) (*CredentialVerification, error)

// VerifyCredential calls f.
func (f CredentialVerifierFunc) VerifyCredential(ctx context.Context, req CredentialVerificationRequest) (*CredentialVerification, error) {
	return f(ctx, req)
}

// CredentialVerificationRequest is the input to CredentialVerifier.
type CredentialVerificationRequest struct {
	// Token is the credential exactly as the wallet presented it.
	Token string
	// Query is the resolved credential query the token answers.
	Query ResolvedCredentialQuery
	// Nonce is the session nonce the holder-binding proof must carry.
	Nonce string
	// ClientID is the audience the holder-binding proof must name.
	ClientID string
	// Matcher is the matcher the caller passed to HandleWalletResponse.
	Matcher openid4vp.TrustedAuthorityMatcher
}

// CredentialVerification is the outcome for a credential that passed.
type CredentialVerification struct {
	// Issuer identifies the credential issuer.
	Issuer string
	// TrustStatus is a registered value other than "invalid".
	TrustStatus TrustStatus
	// HolderBinding is the verified binding; "key_binding" when the RP
	// requires cryptographic holder binding.
	HolderBinding HolderBinding
	// ProtectedHeaders holds only headers covered by the verified signature.
	ProtectedHeaders map[string]any
}
