**tl;dr-** copy & paste from here instead of Stack Overflow

This library contains a selection of acceptable basic cryptography from the Go
standard library. To the extent possible, it tries to hide complexity and help
you avoid common mistakes. The recommendations were chosen as a compromise
between cryptographic qualities, the Go standard lib, and some specific use
cases. Two particular caveats to the strict copy & paste strategy are:

1. SHA512/256 is still a little odd. It has better 64-bit performance and
   resistance to some attacks that affect normal SHA-256, but you won't see it
   in standards yet. If you need normal SHA-256, it's provided as `HashSHA256`.

2. The specific ECDSA parameters were chosen to work with RFC7518 (i.e. signed
   JWTs). You might have better options!

## Recommendations

Encryption: nacl secretbox with random 192-bit nonces

Hashing: SHA-512/256 (preferred) or SHA-256 (compatible)

Password hashing: bcrypt with work factor 12

Message Authentication: HMAC-SHA512/256

Signing: ECDSA on P256 with SHA256 message digests
