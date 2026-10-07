package credbridge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
)

// assemblePresentedCredentialSets turns the presentation result into the
// array shape defined in Section 5.1.1. When the request carried
// credential_sets, each set is emitted from its first fully-satisfied
// option; an unsatisfied REQUIRED set yields access_denied, while an
// unsatisfied optional set is dropped rather than replaced by an
// uncorrelated fallback. The single uncorrelated set is emitted only
// when the request carried no credential_sets at all (scope-based mode).
func (o *OP) assemblePresentedCredentialSets(result *OPPresentationResult) (PresentedCredentialSets, error) {
	if result == nil {
		return nil, fmt.Errorf("%w: nil presentation result", ErrOPAccessDenied)
	}
	if !result.CredentialSetsRequested {
		return PresentedCredentialSets{{Credentials: cloneEntries(result.Entries)}}, nil
	}
	sets := make(PresentedCredentialSets, 0, len(result.SatisfiedSets))
	for _, s := range result.SatisfiedSets {
		set := PresentedCredentialSet{CredentialSetID: s.ID, Credentials: map[string][]CredentialEntry{}}
		for _, option := range s.Options {
			satisfied := true
			for _, id := range option {
				if len(result.Entries[id]) == 0 {
					satisfied = false
					break
				}
			}
			if !satisfied {
				continue
			}
			for _, id := range option {
				set.Credentials[id] = append([]CredentialEntry(nil), result.Entries[id]...)
			}
			break
		}
		if len(set.Credentials) > 0 {
			sets = append(sets, set)
			continue
		}
		if s.Required {
			return nil, fmt.Errorf("%w: required credential set %q is unsatisfied", ErrOPAccessDenied, s.ID)
		}
	}
	return sets, nil
}

// cloneEntries returns a deep-ish copy of the entries map (the
// CredentialEntry values are shared).
func cloneEntries(in map[string][]CredentialEntry) map[string][]CredentialEntry {
	out := make(map[string][]CredentialEntry, len(in))
	for k, v := range in {
		out[k] = append([]CredentialEntry(nil), v...)
	}
	return out
}

// deriveSub implements Section 5.5.
func (o *OP) deriveSub(opSession *OPSession, sets PresentedCredentialSets) (string, error) {
	entry, sourceKey, err := sets.selectIdentityEntry()
	if err != nil {
		return "", err
	}
	cfg, ok := o.subjectClaimConfigFor(opSession, sourceKey)
	if !ok || len(cfg.SubjectClaim) == 0 {
		return "", fmt.Errorf("%w: no subject_claim configured for credential type %q", ErrOPAccessDenied, sourceKey)
	}
	// Read the subject from the preserved unfiltered claims so a stable
	// identifier the RP chose not to disclose is still available here.
	subjectClaims := entry.Claims
	if entry.subjectSource != nil {
		subjectClaims = entry.subjectSource
	}
	raw, ok := lookupClaim(subjectClaims, cfg.SubjectClaim)
	if !ok {
		return "", fmt.Errorf("%w: identity credential missing subject claim %v", ErrOPAccessDenied, cfg.SubjectClaim)
	}
	if o.cfg.SubjectType == OPSubjectTypePublic {
		// OIDC sub is a string identifier; coercing an arbitrary JSON value
		// with %v is not injective ("1" and 1 collide) and an empty value is
		// not a valid subject, so require a non-empty string.
		s, ok := raw.(string)
		if !ok || s == "" {
			return "", fmt.Errorf("%w: subject claim %v must be a non-empty string", ErrOPAccessDenied, cfg.SubjectClaim)
		}
		return s, nil
	}
	// Canonically encode the typed subject claim and length-prefix each
	// HMAC component so distinct (client_id, subject) pairs — and subject
	// values of different JSON types such as "1" and 1 — can never hash to
	// the same pairwise sub.
	subjectBytes, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("%w: encode subject claim: %v", ErrOPAccessDenied, err)
	}
	h := hmac.New(sha256.New, o.cfg.PairwiseSalt)
	writeLengthPrefixed(h, []byte(opSession.ClientID))
	writeLengthPrefixed(h, subjectBytes)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// writeLengthPrefixed writes an 8-byte big-endian length header followed
// by b so that components concatenated into an HMAC are unambiguous
// regardless of the bytes each component contains.
func writeLengthPrefixed(h hash.Hash, b []byte) {
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], uint64(len(b)))
	h.Write(hdr[:])
	h.Write(b)
}

// subjectClaimConfigFor returns the configured OPCredentialTypeConfig
// for the credential key that sourced the subject. In scope-based mode
// the key is the scope itself; in DCQL-based mode the key is the RP's
// opaque Credential Query id, so the scope the OP bound to that id at
// authorization time (ResolvedCredentialQuery.Scope) is used to recover
// the configuration (§5.5 rule 3).
func (o *OP) subjectClaimConfigFor(opSession *OPSession, key string) (OPCredentialTypeConfig, bool) {
	if cfg, ok := o.cfg.CredentialPresentations[key]; ok {
		return cfg, true
	}
	for _, rq := range opSession.DCQL.Credentials {
		if rq.ID == key && rq.Scope != "" {
			if cfg, ok := o.cfg.CredentialPresentations[rq.Scope]; ok {
				return cfg, true
			}
		}
	}
	return OPCredentialTypeConfig{}, false
}

// selectIdentityEntry implements the three-rule selection of §5.5.
func (s PresentedCredentialSets) selectIdentityEntry() (CredentialEntry, string, error) {
	// Rule 1: any entry with primary=true.
	for _, set := range s {
		for _, key := range sortedKeys(set.Credentials) {
			for _, e := range set.Credentials[key] {
				if e.Primary {
					return e, key, nil
				}
			}
		}
	}
	if len(s) == 0 {
		return CredentialEntry{}, "", fmt.Errorf("%w: no credential sets", ErrOPAccessDenied)
	}
	// Rule 2: exactly one Credential Entry across all Credential Sets.
	if s.totalEntries() == 1 {
		for _, set := range s {
			for _, key := range sortedKeys(set.Credentials) {
				if len(set.Credentials[key]) == 1 {
					return set.Credentials[key][0], key, nil
				}
			}
		}
	}
	// Rule 3: implementation-defined. Pick the entry with the
	// lexicographically-smallest (credential_set_id, credential key)
	// pair. §5.1.1 says outer array order is not significant, so we do
	// not depend on it.
	type candidate struct {
		setID, key string
		entry      CredentialEntry
	}
	var best *candidate
	for _, set := range s {
		for _, key := range sortedKeys(set.Credentials) {
			entries := set.Credentials[key]
			if len(entries) == 0 {
				continue
			}
			c := candidate{setID: set.CredentialSetID, key: key, entry: entries[0]}
			if best == nil || c.setID < best.setID || (c.setID == best.setID && c.key < best.key) {
				best = &c
			}
		}
	}
	if best != nil {
		return best.entry, best.key, nil
	}
	return CredentialEntry{}, "", fmt.Errorf("%w: no identity credential", ErrOPAccessDenied)
}

// totalEntries returns the total number of Credential Entries across
// every Credential Set in s.
func (s PresentedCredentialSets) totalEntries() int {
	n := 0
	for _, set := range s {
		n += set.entryCount()
	}
	return n
}

// entryCount returns the number of Credential Entries in this set.
func (set PresentedCredentialSet) entryCount() int {
	n := 0
	for _, v := range set.Credentials {
		n += len(v)
	}
	return n
}

// sortedKeys returns m's keys in ascending lexicographic order so
// iteration is deterministic (used by §5.5 rule 3 selection).
func sortedKeys(m map[string][]CredentialEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
