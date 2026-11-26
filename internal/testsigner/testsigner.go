// Package testsigner provides fixture signers and helpers for the
// example tests in the credbridge module. It is not a public API and
// must not be imported by production callers.
package testsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"maps"
	"math/big"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/golang-jwt/jwt/v5"
)

// signer implements pki.Signer with an ephemeral P-256 key.
type signer struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func (s *signer) Algorithm() string { return "ES256" }
func (s *signer) KeyID() string     { return s.kid }
func (s *signer) PublicKey() any    { return &s.priv.PublicKey }
func (s *signer) Sign(_ context.Context, data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, sum[:])
	if err != nil {
		return nil, err
	}
	return append(padBigInt(r, 32), padBigInt(ss, 32)...), nil
}

func padBigInt(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// MustNew returns an ephemeral ES256 signer suitable for tests.
func MustNew() pki.Signer {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &signer{priv: priv, kid: "test-key"}
}

// MustIssueJWT signs a compact JWT with typ=vc+sd-jwt and the given
// claims, using s. Panics on failure. The token is a valid input for
// openid4vp.ClaimsExtractor since it also accepts SD-JWT VC tokens with
// no selective disclosures.
func MustIssueJWT(s pki.Signer, claims map[string]any) string {
	body := jwt.MapClaims{}
	maps.Copy(body, claims)
	tok, err := jose.MakeJWT(context.Background(), jwt.MapClaims{"typ": "vc+sd-jwt"}, body, s)
	if err != nil {
		panic(err)
	}
	return tok
}

// DecodeUnverified base64url-decodes the body of a JWS and returns the
// parsed claim map, ignoring the signature.
func DecodeUnverified(token string) (map[string]any, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, claims); err != nil {
		return nil, err
	}
	out := map[string]any{}
	maps.Copy(out, claims)
	return out, nil
}
