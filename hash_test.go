package cryptopasta

import "testing"

const (
	BcryptPassword = "password"
	BcryptHash     = "$2b$12$6aRTFGpxnLRH3nX6U45B5uDbsyLGMWRo.l88PXkp6Eo5HPZfUDdju"
)

func TestPasswordHashing(t *testing.T) {
	hashed, err := HashPassword([]byte(BcryptPassword))
	if err != nil {
		t.Fatal(err)
	}

	if err = CheckPassword(hashed, []byte(BcryptPassword)); err != nil {
		t.Error(err)
	}
}
