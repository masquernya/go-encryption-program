package encryption

import (
	crypto_ran "crypto/rand"
	"golang.org/x/crypto/nacl/box"
)

const (
	MagicBytesVersion1 string = "OwO1"
)

func GenerateKeys() ([]byte, []byte, error) {
	publicKey, privateKey, err := box.GenerateKey(crypto_ran.Reader)
	if err != nil {
		panic(err)
	}
	return publicKey[:], privateKey[:], nil
}

const defaultBufferSize int = 1024 * 16 // 16kb
