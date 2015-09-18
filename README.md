**tl;dr-** copy & paste from here instead of Stack Overflow

This is an attempt to encode acceptable answers about cryptography. The
primitives and interfaces were chosen as a compromise between cryptographic
qualities, the Go standard lib, and some specific use cases. Two particular
caveats to the strict copy & paste strategy are:

1. SHA512/256 is still a little odd. It has better 64-bit performance and
   resistance to some attacks that affect normal SHA-256, but you won't see it
   in standards yet. If you need SHA-256, it's provided as `HashSHA256`.

2. The specific ECDSA parameters were chosen to work with RFC7518 (i.e. signed
   JWTs). You might have better options!

## Recommendations

Encryption: 256-bit AES-GCM with default 96-bit nonces

Hashing: SHA-512/256 (preferred) or SHA-256 (compatible)

Message Authentication: HMAC-SHA512/256

Signatures: ECDSA on P256 with SHA256 message digests

## Usage

Encryption
```
message := []byte("Hello, world!")
key, err := GenerateEncryptionKey()

ciphertext, err := Encrypt(message, key)
plaintext, err := Decrypt(ciphertext, key)
```

Hashing
```
message := []byte("Hello, world!")
digest  := Hash(message)
```

Signing
```
message := []byte("Hello, world!")
key, err := GenerateSigningKey()

signature, err := Sign(message, key)
signatureBytes, err := EncodeSignatureASN1(signature)

decodedSignature, err := DecodeSignatureASN1(signatureBytes)
isSignatureValid := Verify(message, decodedSignature, &key.PublicKey)
```
