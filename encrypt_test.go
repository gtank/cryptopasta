package cryptopasta

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptGCM(t *testing.T) {
	TestData := []byte("Hello, world!")

	key, _ := GenerateEncryptionKey()

	ciphertext, err := Encrypt(TestData, key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, TestData) {
		t.Errorf("plaintexts don't match")
	}

	ciphertext[0] ^= 0xff
	plaintext, err = Decrypt(ciphertext, key)
	if err == nil {
		t.Errorf("gcmOpen should not have worked, but did")
	}
}
