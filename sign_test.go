package cryptopasta

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

var (
	// https://groups.google.com/d/msg/sci.crypt/OolWgsgQD-8/jHciyWkaL0gJ
	HMACKey     = []byte("Jefe")
	HMACMessage = []byte("what do ya want for nothing?")
	HMACDigest  = "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"
)

func TestHMACGeneration(t *testing.T) {
	mac := GenerateHMAC(HMACMessage, HMACKey)

	// note: don't ever actually check HMACs this way
	if strings.Compare(fmt.Sprintf("%x", mac), HMACDigest) != 0 {
		t.Fail()
	}
}

func TestHMACValidation(t *testing.T) {
	expectedBytes, _ := hex.DecodeString(HMACDigest)
	if !ValidateHMAC(HMACMessage, expectedBytes, HMACKey) {
		t.Fail()
	}
}

func TestSigningKeyCheck(t *testing.T) {
	wrongCurveKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}

	message := []byte("Hello, world!")

	_, err = Sign(message, wrongCurveKey)
	if err != ErrorInvalidParams {
		t.Error("didn't notice the wrong curve")
		return
	}
}

func TestSignAndVerify(t *testing.T) {
	message := []byte("Hello, world!")

	key, err := GenerateSigningKey()
	if err != nil {
		t.Error(err)
		return
	}

	signature, err := Sign(message, key)
	if err != nil {
		t.Error(err)
		return
	}

	if !Verify(message, signature, &key.PublicKey) {
		t.Error("signature was not correct")
		return
	}

	message[0] ^= 0xff
	if Verify(message, signature, &key.PublicKey) {
		t.Error("signature was good for altered message")
	}
}

func TestASNEncodeDecode(t *testing.T) {
	message := []byte("Hello, world!")

	key, err := GenerateSigningKey()
	if err != nil {
		t.Error(err)
		return
	}

	signature, err := Sign(message, key)
	if err != nil {
		t.Error(err)
		return
	}

	sigBytes, err := EncodeSignatureASN1(signature)
	if err != nil {
		t.Error(err)
		return
	}

	decodedSig, err := DecodeSignatureASN1(sigBytes)
	if err != nil {
		t.Error(err)
		return
	}

	if !Verify(message, decodedSig, &key.PublicKey) {
		t.Error("signature was not correct")
	}
}

// Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.3.1
func TestJWTEncoding(t *testing.T) {
	rBytes := []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21,
		88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158,
		166, 101}

	sBytes := []byte{197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
		8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131,
		163, 84, 213}

	expectedResult := "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	sig := new(ECDSASignature)
	sig.R = big.NewInt(0).SetBytes(rBytes)
	sig.S = big.NewInt(0).SetBytes(sBytes)
	result := EncodeSignatureJWT(sig)

	if strings.Compare(result, expectedResult) != 0 {
		t.Fatalf("expected %s, got %s\n", expectedResult, result)
	}
}

func TestJWTDecoding(t *testing.T) {
	rBytes := []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21,
		88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158,
		166, 101}

	sBytes := []byte{197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
		8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131,
		163, 84, 213}

	expectedSig := new(ECDSASignature)
	expectedSig.R = big.NewInt(0).SetBytes(rBytes)
	expectedSig.S = big.NewInt(0).SetBytes(sBytes)

	testSig := "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	resultSig, err := DecodeSignatureJWT(testSig)
	if err != nil {
		t.Error(err)
	}

	if resultSig.R.Cmp(expectedSig.R) != 0 || resultSig.S.Cmp(expectedSig.S) != 0 {
		t.Fatalf("decoded signature was incorrect")
	}

}
