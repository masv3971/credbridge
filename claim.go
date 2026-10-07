package credbridge

import (
	"encoding/json"
	"fmt"
)

// PresentedCredentialSetsClaim is the JWT/UserInfo claim name defined in
// Section 8.1 of the draft.
const PresentedCredentialSetsClaim = "presented_credential_sets"

// PresentedCredentialSet is one entry in the top-level
// "presented_credential_sets" array (Section 5.1.1).
type PresentedCredentialSet struct {
	// CredentialSetID echoes the RP-supplied DCQL Credential Set "id" when
	// the request used the DCQL-based mode; empty in scope-based mode.
	CredentialSetID string `json:"credential_set_id,omitempty"`

	// Credentials is keyed by credential type scope value (scope-based
	// mode) or DCQL Credential Query "id" (DCQL-based mode). Each value is
	// one or more CredentialEntry objects, one per credential the wallet
	// presented for that key.
	Credentials map[string][]CredentialEntry `json:"credentials"`
}

// PresentedCredentialSets is the top-level "presented_credential_sets"
// value delivered in the ID Token or UserInfo response.
type PresentedCredentialSets []PresentedCredentialSet

// CredentialEntry is a single presented credential (Section 5.1.2). Every
// entry MUST carry Type and Verification; exactly one of Claims or
// Namespaces MUST be populated.
type CredentialEntry struct {
	Type             []string                  `json:"type"`
	Issuer           string                    `json:"issuer,omitempty"`
	ValidFrom        int64                     `json:"valid_from,omitempty"`
	ValidUntil       int64                     `json:"valid_until,omitempty"`
	VerifiedAt       int64                     `json:"verified_at,omitempty"`
	Verification     *Verification             `json:"verification,omitempty"`
	Claims           map[string]any            `json:"claims,omitempty"`
	Namespaces       map[string]map[string]any `json:"namespaces,omitempty"`
	Digest           *Digest                   `json:"digest,omitempty"`
	Primary          bool                      `json:"primary,omitempty"`
	AdditionalFields map[string]any            `json:"-"`

	// subjectSource holds the credential's unfiltered claims so subject
	// derivation can read a stable identifier the RP did not request to be
	// disclosed. It is unexported and never relayed to the RP.
	subjectSource map[string]any
}

// EffectiveVerification returns the Verification the RP should reason
// about. When Verification is absent (§5.1.2 permits omission), the RP
// treats it as if the OP had sent {"trust_status": "not_checked"}.
func (e CredentialEntry) EffectiveVerification() Verification {
	if e.Verification == nil {
		return Verification{TrustStatus: TrustStatusNotChecked}
	}
	return *e.Verification
}

// Verification carries metadata about the OP's verification of a
// credential (Section 5.1.2, "verification" member).
type Verification struct {
	HolderBinding    HolderBinding  `json:"holder_binding,omitempty"`
	TrustStatus      TrustStatus    `json:"trust_status"`
	ProtectedHeaders map[string]any `json:"protected_headers,omitempty"`
	// Crit lists other members of this Verification object that the RP
	// MUST understand to accept the credential (RFC 7515 §4.1.11 style).
	Crit []string `json:"crit,omitempty"`
	// AdditionalMembers holds verification members not modeled above.
	// EvaluateCrit consults this map to satisfy critical members named in
	// Crit.
	AdditionalMembers map[string]any `json:"-"`
}

// Digest is the OPTIONAL one-way digest of the source credential
// (Section 5.1.2).
type Digest struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// TrustStatus is a value from the Credential Trust Status Values registry
// (Section 8.3).
type TrustStatus string

// Credential Trust Status Values (Section 8.3).
const (
	TrustStatusNotChecked TrustStatus = "not_checked"
	TrustStatusUnknown    TrustStatus = "unknown"
	TrustStatusValid      TrustStatus = "valid"
	TrustStatusSuspended  TrustStatus = "suspended"
	TrustStatusRevoked    TrustStatus = "revoked"
	TrustStatusExpired    TrustStatus = "expired"
	TrustStatusInvalid    TrustStatus = "invalid"
)

// IsRegistered reports whether v is one of the values from the initial
// contents of the Section 8.3 registry.
func (v TrustStatus) IsRegistered() bool {
	switch v {
	case TrustStatusNotChecked, TrustStatusUnknown, TrustStatusValid,
		TrustStatusSuspended, TrustStatusRevoked, TrustStatusExpired,
		TrustStatusInvalid:
		return true
	}
	return false
}

// HolderBinding is a value from the Credential Holder Binding Methods
// registry (Section 8.4).
type HolderBinding string

// Credential Holder Binding Methods (Section 8.4).
const (
	HolderBindingKey       HolderBinding = "key_binding"
	HolderBindingBiometric HolderBinding = "biometric"
	HolderBindingPIN       HolderBinding = "pin"
)

// IsRegistered reports whether v is one of the values from the initial
// contents of the Section 8.4 registry.
func (v HolderBinding) IsRegistered() bool {
	switch v {
	case HolderBindingKey, HolderBindingBiometric, HolderBindingPIN:
		return true
	}
	return false
}

// reservedEntryKeys is the full set of JSON member names the typed
// CredentialEntry model owns (§5.1.2). AdditionalFields may not use any
// of them, even when the typed value is currently empty and would be
// dropped by omitempty.
var reservedEntryKeys = map[string]struct{}{
	"type": {}, "issuer": {}, "valid_from": {}, "valid_until": {},
	"verified_at": {}, "verification": {}, "claims": {},
	"namespaces": {}, "digest": {}, "primary": {},
}

// reservedVerificationKeys is the full set of JSON member names the typed
// Verification model owns (§5.1.2).
var reservedVerificationKeys = map[string]struct{}{
	"holder_binding": {}, "trust_status": {}, "protected_headers": {}, "crit": {},
}

// MarshalJSON serialises a CredentialEntry, flattening any
// AdditionalFields into the top level of the JSON object.
func (e CredentialEntry) MarshalJSON() ([]byte, error) {
	type alias CredentialEntry
	base, err := json.Marshal(alias(e))
	if err != nil {
		return nil, err
	}
	if len(e.AdditionalFields) == 0 {
		return base, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		return nil, err
	}
	for k, v := range e.AdditionalFields {
		if _, reserved := reservedEntryKeys[k]; reserved {
			return nil, fmt.Errorf("credbridge: additional field %q collides with a reserved member", k)
		}
		if _, exists := obj[k]; exists {
			return nil, fmt.Errorf("credbridge: additional field %q collides with a reserved member", k)
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("credbridge: additional field %q: %w", k, err)
		}
		obj[k] = raw
	}
	return json.Marshal(obj)
}

// UnmarshalJSON decodes a CredentialEntry and captures any unknown
// top-level members in AdditionalFields so that RPs can evaluate crit
// against them.
func (e *CredentialEntry) UnmarshalJSON(data []byte) error {
	type alias CredentialEntry
	var typed alias
	if err := json.Unmarshal(data, &typed); err != nil {
		return err
	}
	*e = CredentialEntry(typed)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var extras map[string]any
	for k, v := range raw {
		if _, ok := reservedEntryKeys[k]; ok {
			continue
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return fmt.Errorf("credbridge: additional field %q: %w", k, err)
		}
		if extras == nil {
			extras = make(map[string]any)
		}
		extras[k] = val
	}
	e.AdditionalFields = extras
	return nil
}

// MarshalJSON serialises a Verification, flattening AdditionalMembers.
func (v Verification) MarshalJSON() ([]byte, error) {
	type alias Verification
	base, err := json.Marshal(alias(v))
	if err != nil {
		return nil, err
	}
	if len(v.AdditionalMembers) == 0 {
		return base, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(base, &obj); err != nil {
		return nil, err
	}
	for k, val := range v.AdditionalMembers {
		if _, reserved := reservedVerificationKeys[k]; reserved {
			return nil, fmt.Errorf("credbridge: additional verification member %q collides with a reserved member", k)
		}
		if _, exists := obj[k]; exists {
			return nil, fmt.Errorf("credbridge: additional verification member %q collides with a reserved member", k)
		}
		raw, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("credbridge: additional verification member %q: %w", k, err)
		}
		obj[k] = raw
	}
	return json.Marshal(obj)
}

// UnmarshalJSON decodes a Verification and captures unknown members in
// AdditionalMembers.
func (v *Verification) UnmarshalJSON(data []byte) error {
	type alias Verification
	var typed alias
	if err := json.Unmarshal(data, &typed); err != nil {
		return err
	}
	*v = Verification(typed)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var extras map[string]any
	for k, val := range raw {
		if _, ok := reservedVerificationKeys[k]; ok {
			continue
		}
		var out any
		if err := json.Unmarshal(val, &out); err != nil {
			return fmt.Errorf("credbridge: additional verification member %q: %w", k, err)
		}
		if extras == nil {
			extras = make(map[string]any)
		}
		extras[k] = out
	}
	v.AdditionalMembers = extras
	return nil
}
