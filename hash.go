// Provides a recommended hashing algorithm.
//
// The hash function is SHA512/256 as described in FIPS 180-4. This
// construction avoids length-extension attacks while maintaining a
// widely compatible digest size and potentially seeing performance
// improvements on 64-bit systems.
//
// SHA256 is also provided because it is widely used elsewhere.

package cryptopasta

import (
	"crypto/sha256"
	"crypto/sha512"
)

const (
	DigestSize = sha512.Size256
)

// Hashes data using SHA-512/256
func Hash(data []byte) [DigestSize]byte {
	digest := sha512.Sum512_256(data)
	return digest
}

// Hashes data using SHA256
// Use is not recommended except where necessary to preserve compatibility.
func HashSHA256(data []byte) [DigestSize]byte {
	digest := sha256.Sum256(data)
	return digest
}
