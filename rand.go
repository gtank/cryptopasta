package cryptopasta

import "crypto/rand"

func generateBytes(size int) ([]byte, error) {
	randBytes := make([]byte, size)

	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	return randBytes, nil
}
