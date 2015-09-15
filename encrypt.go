// Provides symmetric authenticated encryption.
//
// Encryption is handled using 256-bit AES-GCM with the standard 96-bit nonce

package cryptopasta

import (
	"crypto/aes"
	"crypto/cipher"
)

const aesKeySize = 32 // force 256-bit AES

// Generates a random 256-bit key
func GenerateEncryptionKey() ([]byte, error) {
	return generateBytes(aesKeySize)
}

// Takes plaintext and a key, result in the format nonce|ciphertext|tag where
// '|' indicates concatenation
func Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	if len(key) != aesKeySize {
		return nil, aes.KeySizeError(len(key))
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	nonce, err := generateBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Takes ciphertext of the form nonce|ciphertext|tag where '|' indicates
// concatenation
func Decrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	if len(key) != aesKeySize {
		return nil, aes.KeySizeError(len(key))
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():], nil)
}
