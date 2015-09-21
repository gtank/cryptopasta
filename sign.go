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
	"encoding/asn1"
	"encoding/base64"
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

// Generates a 256-bit HMAC key
func GenerateHMACKey() ([]byte, error) {
	key, err := generateBytes(hmacKeySize)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Generates symmetric signature using HMAC-SHA512/256
func GenerateHMAC(data, key []byte) []byte {
	mac := hmac.New(hmacHash.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// Checks the supplied MAC against a message using a secure compare function
func ValidateHMAC(data, suppliedMAC, key []byte) bool {
	expectedMAC := GenerateHMAC(data, key)
	return hmac.Equal(expectedMAC, suppliedMAC)
}

// Generates a P-256 ECDSA key using crypto/rand
func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

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

func Verify(data []byte, sig *ECDSASignature, pubkey *ecdsa.PublicKey) bool {
	// hash message
	h := ecdsaHash.New()
	h.Write(data)
	digest := h.Sum(nil)

	return ecdsa.Verify(pubkey, digest, sig.R, sig.S)
}

// Encodes ECDSA signature as an ASN.1 sequence (X9.62 format)
// See RFC3278 Section 8.2 for details
func EncodeSignatureASN1(sig *ECDSASignature) ([]byte, error) {
	return asn1.Marshal(*sig)
}

func DecodeSignatureASN1(sigBytes []byte) (*ECDSASignature, error) {
	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(sigBytes, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Encode according to https://tools.ietf.org/html/rfc7515#appendix-A.3.1
func EncodeSignatureJWT(sig *ECDSASignature) string {
	combinedBytes := append(sig.R.Bytes(), sig.S.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(combinedBytes)
}

func DecodeSignatureJWT(b64sig string) (*ECDSASignature, error) {
	combinedBytes, err := base64.RawURLEncoding.DecodeString(b64sig)
	if err != nil {
		return nil, err
	}

	sig := new(ECDSASignature)
	sig.R = big.NewInt(0).SetBytes(combinedBytes[:ecdsaBitSize/8])
	sig.S = big.NewInt(0).SetBytes(combinedBytes[ecdsaBitSize/8:])
	return sig, nil
}
