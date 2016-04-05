// Provides symmetric authenticated encryption using nacl secretbox with a
// random nonce. The length of the message is not hidden.
package cryptopasta

import (
	"errors"
	"strconv"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize   = 32                 // 256-bit secretbox keys
	NonceSize = 24                 // 192-bit secretbox nonces
	Overhead  = secretbox.Overhead // the size of the poly1305 tag
)

type KeySizeError int

func (err KeySizeError) Error() string {
	return "cryptopasta/encrypt: invalid key size " + strconv.Itoa(int(err))
}

// GenerateEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt().
func GenerateEncryptionKey() ([]byte, error) {
	return generateBytes(KeySize)
}

// Encrypt encrypts data using nacl secretbox. This algorithm both hides the
// content of the data and provides a check that it hasn't been altered. Output
// takes the form nonce|ciphertext|tag where '|' indicates concatenation. The
// output will be Overhead bytes longer than the message.
func Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}

	nonce, err := generateBytes(NonceSize)
	if err != nil {
		return nil, err
	}

	var fixedKey [KeySize]byte
	var fixedNonce [NonceSize]byte
	copy(fixedKey[:], key)
	copy(fixedNonce[:], nonce)

	return secretbox.Seal(nonce, plaintext, &fixedNonce, &fixedKey), nil
}

// Decrypt decrypts data using nacl secretbox. This algorithm both hides the
// content of the data and provides a check that it hasn't been altered. Input
// takes the form form nonce|ciphertext|tag where '|' indicates concatenation.
// Output will be Overhead bytes shorter than the input.
func Decrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}

	var fixedKey [KeySize]byte
	var fixedNonce [NonceSize]byte
	copy(fixedKey[:], key)
	copy(fixedNonce[:], ciphertext[:NonceSize])

	decrypt, ok := secretbox.Open(nil, ciphertext[NonceSize:], &fixedNonce, &fixedKey)
	if !ok {
		return nil, errors.New("cryptopasta/encrypt: secretbox Open failed")
	}
	return decrypt, nil
}
