package credbridge

import (
	"errors"
	"fmt"
)

// EvaluateCrit implements the "verification.crit" semantics of Section
// 5.1.2. It returns nil if every string listed in entry.Verification.Crit
// names a Verification member that is present and whose value is
// recognised by the caller. If Crit is empty, the entry is accepted.
//
// The forbidden literal "crit" is rejected per §5.1.2. Any listed member
// that is absent, or whose value the caller has not declared as
// understood, causes [ErrCritUnknownMember] wrapped with a descriptive
// message.
//
// understoodMembers is the set of Verification member names that the RP
// knows how to interpret. Standard members ("holder_binding",
// "trust_status", "protected_headers") are always considered understood
// by this function; pass names for any additional Verification members
// the RP is prepared to handle.
func EvaluateCrit(entry CredentialEntry, understoodMembers ...string) error {
	if entry.Verification == nil {
		return nil
	}
	crit := entry.Verification.Crit
	if len(crit) == 0 {
		return nil
	}
	understood := map[string]struct{}{
		"holder_binding":    {},
		"trust_status":      {},
		"protected_headers": {},
	}
	for _, m := range understoodMembers {
		understood[m] = struct{}{}
	}
	for _, name := range crit {
		if name == "crit" {
			return fmt.Errorf("credbridge: %w: %q must not appear in crit", ErrCritUnknownMember, name)
		}
		if !entry.Verification.hasMember(name) {
			return fmt.Errorf("credbridge: %w: crit lists %q but it is not a member of verification", ErrCritUnknownMember, name)
		}
		if _, ok := understood[name]; !ok {
			return fmt.Errorf("credbridge: %w: crit member %q is not understood by the RP", ErrCritUnknownMember, name)
		}
	}
	return nil
}

// hasMember reports whether name refers to a populated member of v
// (§5.1.2 verification members).
func (v *Verification) hasMember(name string) bool {
	switch name {
	case "holder_binding":
		return v.HolderBinding != ""
	case "trust_status":
		return v.TrustStatus != ""
	case "protected_headers":
		return v.ProtectedHeaders != nil
	}
	_, ok := v.AdditionalMembers[name]
	return ok
}

// ErrCritUnknownMember is returned when a member listed in
// Verification.Crit is either absent from the Verification object or not
// declared as understood by the RP.
var ErrCritUnknownMember = errors.New("critical verification member not understood")
