package cryptopasta

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
)

// A keypair for NIST P-256 / secp256r1
// Generated using:
//   openssl ecparam -genkey -name prime256v1 -outform PEM
var pemECPrivateKeyP256 = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOI+EZsjyN3jvWJI/KDihFmqTuDpUe/if6f/pgGTBta/oAoGCCqGSM49
AwEHoUQDQgAEhhObKJ1r1PcUw+3REd/TbmSZnDvXnFUSTwqQFo5gbfIlP+gvEYba
+Rxj2hhqjfzqxIleRK40IRyEi3fJM/8Qhg==
-----END EC PRIVATE KEY-----
`

var pemECPublicKeyP256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhhObKJ1r1PcUw+3REd/TbmSZnDvX
nFUSTwqQFo5gbfIlP+gvEYba+Rxj2hhqjfzqxIleRK40IRyEi3fJM/8Qhg==
-----END PUBLIC KEY-----
`

// A keypair for NIST P-384 / secp384r1
// Generated using:
//   openssl ecparam -genkey -name secp384r1 -outform PEM
var pemECPrivateKeyP384 = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAhA0YPVL1kimIy+FAqzUAtmR3It2Yjv2I++YpcC4oX7wGuEWcWKBYE
oOjj7wG/memgBwYFK4EEACKhZANiAAQub8xaaCTTW5rCHJCqUddIXpvq/TxdwViH
+tPEQQlJAJciXStM/aNLYA7Q1K1zMjYyzKSWz5kAh/+x4rXQ9Hlm3VAwCQDVVSjP
bfiNOXKOWfmyrGyQ7fQfs+ro1lmjLjs=
-----END EC PRIVATE KEY-----
`

var pemECPublicKeyP384 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELm/MWmgk01uawhyQqlHXSF6b6v08XcFY
h/rTxEEJSQCXIl0rTP2jS2AO0NStczI2Msykls+ZAIf/seK10PR5Zt1QMAkA1VUo
z234jTlyjln5sqxskO30H7Pq6NZZoy47
-----END PUBLIC KEY-----
`

var garbagePEM = `-----BEGIN GARBAGE-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=
-----END GARBAGE-----
`

func TestPublicKeyMarshaling(t *testing.T) {
	ecKey, err := DecodePublicKey([]byte(pemECPublicKeyP256))
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, _ := EncodePublicKey(ecKey)
	if !bytes.Equal(pemBytes, []byte(pemECPublicKeyP256)) {
		t.Fatal("public key encoding did not match")
	}

}

func TestPrivateKeyBadDecode(t *testing.T) {
	_, err := DecodePrivateKey([]byte(garbagePEM))
	if err == nil {
		t.Fatal("decoded garbage data without complaint")
	}
}

func TestPrivateKeyMarshaling(t *testing.T) {
	ecKey, err := DecodePrivateKey([]byte(pemECPrivateKeyP256))
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, _ := EncodePrivateKey(ecKey)
	if !strings.HasSuffix(pemECPrivateKeyP256, string(pemBytes)) {
		t.Fatal("private key encoding did not match")
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
var jwtTest = []struct {
	rBytes []byte
	sBytes []byte
	b64sig string
}{
	{
		rBytes: []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21,
			88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158,
			166, 101},
		sBytes: []byte{197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
			8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131,
			163, 84, 213},
		b64sig: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
	},
}

func TestJWTEncoding(t *testing.T) {
	for _, tt := range jwtTest {
		sig := new(ECDSASignature)
		sig.R = big.NewInt(0).SetBytes(tt.rBytes)
		sig.S = big.NewInt(0).SetBytes(tt.sBytes)
		result := EncodeSignatureJWT(sig)

		if strings.Compare(result, tt.b64sig) != 0 {
			t.Fatalf("expected %s, got %s\n", tt.b64sig, result)
		}
	}
}

func TestJWTDecoding(t *testing.T) {
	for _, tt := range jwtTest {
		expectedSig := new(ECDSASignature)
		expectedSig.R = big.NewInt(0).SetBytes(tt.rBytes)
		expectedSig.S = big.NewInt(0).SetBytes(tt.sBytes)

		resultSig, err := DecodeSignatureJWT(tt.b64sig)
		if err != nil {
			t.Error(err)
		}

		if resultSig.R.Cmp(expectedSig.R) != 0 || resultSig.S.Cmp(expectedSig.S) != 0 {
			t.Fatalf("decoded signature was incorrect")
		}
	}
}
