package cryptopasta

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// DecodePublicKey decodes a PEM-encoded ECDSA public key.
func DecodePublicKey(encodedKey []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("marshal: could not decode PEM block type %s", block.Type)

	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("marshal: data was not an ECDSA public key")
	}

	return ecdsaPub, nil
}

// EncodePublicKey encodes an ECDSA public key to PEM format.
func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// Encodes an ECDSA signature as an ASN.1 sequence (X9.62 format)
// See RFC3278 Section 8.2 for details
func EncodeSignatureASN1(sig *ECDSASignature) ([]byte, error) {
	return asn1.Marshal(*sig)
}

// Decodes an ECDSA signature from  an ASN.1 sequence (X9.62 format)
// See RFC3278 Section 8.2 for details
func DecodeSignatureASN1(sigBytes []byte) (*ECDSASignature, error) {
	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(sigBytes, sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Encodes an ECDSA signature according to https://tools.ietf.org/html/rfc7515#appendix-A.3.1
func EncodeSignatureJWT(sig *ECDSASignature) string {
	combinedBytes := append(sig.R.Bytes(), sig.S.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(combinedBytes)
}

// Decodes an ECDSA signature according to https://tools.ietf.org/html/rfc7515#appendix-A.3.1
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
