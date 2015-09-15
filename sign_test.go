package cryptopasta

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	if !(strings.Compare(fmt.Sprintf("%x", mac), HMACDigest) == 0) {
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

func TestASNEncoding(t *testing.T) {
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
