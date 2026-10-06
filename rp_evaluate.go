package credbridge

import "fmt"

// EvaluatePresentedCredentialSets performs the Section 4.2 checks the
// draft requires of every Relying Party:
//
//  1. presented_credential_sets must be present (essential requests).
//  2. Each Credential Entry conforms to the Section 5.1.2 structure
//     (non-empty type, exactly one of claims/namespaces, and a
//     trust_status whenever a verification object is present).
//  3. For every Credential Entry, Verification.Crit must be satisfied
//     via [EvaluateCrit].
//  4. Unknown top-level members of a Credential Entry that are not
//     listed in crit are silently ignored (§4.2 item 4).
//
// understoodVerificationMembers is the set of additional Verification
// members the RP claims to understand. Standard members
// (holder_binding, trust_status, protected_headers) are always
// considered understood; pass additional member names if your RP
// implements support for OP-specific extensions.
func (rc *RPClaims) EvaluatePresentedCredentialSets(understoodVerificationMembers ...string) error {
	if rc == nil || len(rc.PresentedCredentialSets) == 0 {
		return ErrRPPresentedSetsMissing
	}
	for si, set := range rc.PresentedCredentialSets {
		if len(set.Credentials) == 0 {
			return fmt.Errorf("%w: credential set %d has no credentials", ErrRPUnexpectedResponseShape, si)
		}
		for key, entries := range set.Credentials {
			if len(entries) == 0 {
				return fmt.Errorf("%w: credential set %d %q has no credential entries", ErrRPUnexpectedResponseShape, si, key)
			}
			for ei, entry := range entries {
				if err := validateEntryStructure(entry); err != nil {
					return fmt.Errorf("credbridge/rp: set %d %q entry %d: %w", si, key, ei, err)
				}
				if err := EvaluateCrit(entry, understoodVerificationMembers...); err != nil {
					return fmt.Errorf("credbridge/rp: set %d %q entry %d: %w", si, key, ei, err)
				}
			}
		}
	}
	return nil
}

// validateEntryStructure enforces the Section 5.1.2 shape of a Credential
// Entry before any crit evaluation: type is required, exactly one of
// claims or namespaces must be populated, and a present verification
// object must carry the required trust_status member.
func validateEntryStructure(e CredentialEntry) error {
	if len(e.Type) == 0 {
		return fmt.Errorf("%w: credential entry is missing the required type", ErrRPUnexpectedResponseShape)
	}
	hasClaims := len(e.Claims) > 0
	hasNamespaces := len(e.Namespaces) > 0
	if hasClaims == hasNamespaces {
		return fmt.Errorf("%w: credential entry must populate exactly one of claims or namespaces", ErrRPUnexpectedResponseShape)
	}
	if e.Verification != nil && e.Verification.TrustStatus == "" {
		return fmt.Errorf("%w: verification present without the required trust_status", ErrRPUnexpectedResponseShape)
	}
	return nil
}

// Entries returns all Credential Entries whose enclosing set has the
// given credential set id and whose key inside Credentials equals
// credentialKey. Pass "" for setKey to match any set.
func (rc *RPClaims) Entries(setKey, credentialKey string) []CredentialEntry {
	if rc == nil {
		return nil
	}
	var out []CredentialEntry
	for _, set := range rc.PresentedCredentialSets {
		if setKey != "" && set.CredentialSetID != setKey {
			continue
		}
		out = append(out, set.Credentials[credentialKey]...)
	}
	return out
}

// FirstEntry returns the first Credential Entry matching setKey and
// credentialKey. The bool is false when no match exists. See Entries
// for the setKey wildcard rule.
func (rc *RPClaims) FirstEntry(setKey, credentialKey string) (CredentialEntry, bool) {
	entries := rc.Entries(setKey, credentialKey)
	if len(entries) == 0 {
		return CredentialEntry{}, false
	}
	return entries[0], true
}
