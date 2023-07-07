package encryption

import (
	crypto_ran "crypto/rand"
	"errors"
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

// Encrypt encrypts the plainText using publicKey and returns the encrypted text.
func Encrypt(publicKey []byte, plainText []byte) ([]byte, error) {
	data, err := box.SealAnonymous(nil, plainText, (*[32]byte)(publicKey), crypto_ran.Reader)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Decrypt decrypts the encryptedData using privateKey and returns the plain text.
func Decrypt(publicKey []byte, privateKey []byte, encryptedData []byte) ([]byte, error) {
	data, ok := box.OpenAnonymous(nil, encryptedData, (*[32]byte)(publicKey), (*[32]byte)(privateKey))
	if !ok {
		return nil, errors.New("decryption failed")
	}
	return data, nil
}
