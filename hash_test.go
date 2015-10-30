package cryptopasta

import "testing"

func TestPasswordHashing(t *testing.T) {
	bcryptTests := []struct {
		plaintext []byte
		hash      []byte
	}{
		{
			plaintext: []byte("password"),
			hash:      []byte("$2b$12$6aRTFGpxnLRH3nX6U45B5uDbsyLGMWRo.l88PXkp6Eo5HPZfUDdju"),
		},
	}

	for _, tt := range bcryptTests {
		hashed, err := HashPassword(tt.plaintext)
		if err != nil {
			t.Fatal(err)
		}

		if err = CheckPassword(hashed, tt.plaintext); err != nil {
			t.Fatal(err)
		}
	}
}
