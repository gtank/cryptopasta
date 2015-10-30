package cryptopasta

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptGCM(t *testing.T) {
	randomKey, err := generateBytes(aesKeySize)
	if err != nil {
		t.Fatal(err)
	}

	gcmTests := []struct {
		plaintext []byte
		key       []byte
	}{
		{
			plaintext: []byte("Hello, world!"),
			key:       append([]byte("shark"), make([]byte, 27)...),
		},
		{
			plaintext: []byte("Hello, world!"),
			key:       randomKey,
		},
	}

	for _, tt := range gcmTests {
		ciphertext, err := Encrypt(tt.plaintext, tt.key)
		if err != nil {
			t.Fatal(err)
		}

		plaintext, err := Decrypt(ciphertext, tt.key)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(plaintext, tt.plaintext) {
			t.Errorf("plaintexts don't match")
		}

		ciphertext[0] ^= 0xff
		plaintext, err = Decrypt(ciphertext, tt.key)
		if err == nil {
			t.Errorf("gcmOpen should not have worked, but did")
		}
	}
}
