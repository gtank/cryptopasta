// Provides symmetric and asymmetric signatures.
//
// Symmetric Signature: HMAC SHA512/256
// This is a slight twist on the highly dependable HMAC-SHA256 that gains
// performance on 64-bit systems and consistency with our hashing
// recommendation.
//
// Asymmetric Signature: ECDSA using P256 and SHA256
// ECDSA is the best compromise between cryptographic concerns and support for
// our internal use cases (e.g. RFC7518). The Go standard library
// implementation has some protection against entropy problems, but is not
// deterministic. See
// https://github.com/golang/go/commit/8d7bf2291b095d3a2ecaa2609e1101be46d80deb

package cryptopasta

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	ecdsaHash    = crypto.SHA256
	ecdsaBitSize = 256 // 256-bit curve

	hmacHash    = crypto.SHA512_256
	hmacKeySize = 32 // 256-bit key
)

var (
	ErrorInvalidParams = errors.New("ecdsa: invalid curve params")
)

// Encoding differs depending on signature standard
type ECDSASignature struct {
	R, S *big.Int
}

// GenerateHMACKey generates a random 256-bit secret key for HMAC use.
func GenerateHMACKey() ([]byte, error) {
	key, err := generateBytes(hmacKeySize)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GenerateHMAC produces a symmetric signature using HMAC-SHA512/256.
func GenerateHMAC(data, key []byte) []byte {
	mac := hmac.New(hmacHash.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ValidateHMAC securely checks the supplied MAC against a message.
func ValidateHMAC(data, suppliedMAC, key []byte) bool {
	expectedMAC := GenerateHMAC(data, key)
	return hmac.Equal(expectedMAC, suppliedMAC)
}

// GenerateSigningKey generates a random P-256 ECDSA private key.
func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

// Sign signs arbitrary data using ECDSA. The resulting signature should be
// encoded using the approriate Marshal* function for your use case.
func Sign(data []byte, privkey *ecdsa.PrivateKey) (sig *ECDSASignature, err error) {
	// perform some sanity checks
	params := privkey.Curve.Params()

	if params.BitSize != ecdsaBitSize {
		return nil, ErrorInvalidParams
	}

	// hash message
	h := ecdsaHash.New()
	h.Write(data)
	digest := h.Sum(nil)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest)
	if err != nil {
		return nil, err
	}

	return &ECDSASignature{r, s}, nil
}

// Verify checks a raw ECDSA signature.
// Returns true if it's valid and false if not.
func Verify(data []byte, sig *ECDSASignature, pubkey *ecdsa.PublicKey) bool {
	// hash message
	h := ecdsaHash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return ecdsa.Verify(pubkey, digest, sig.R, sig.S)
}
