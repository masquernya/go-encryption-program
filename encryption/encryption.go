package encryption

import (
	"github.com/masquernya/go-encryption-program/encryption/box"
)

const (
	MagicBytesVersion1 string = "OwO1"
)

func GenerateKeys() ([]byte, []byte, error) {
	return box.GenerateKeys()
}

const defaultBufferSize int = 1024 * 16 // 16kb

// PublicKeyEncrypt encrypts the plainText using publicKey and returns the encrypted text.
func PublicKeyEncrypt(publicKey []byte, plainText []byte) ([]byte, error) {
	return box.Encrypt(publicKey, plainText)
}

// PublicKeyDecrypt decrypts the encryptedData using privateKey and returns the plain text.
func PublicKeyDecrypt(privateKey []byte, encryptedData []byte) ([]byte, error) {
	return box.Decrypt(privateKey, encryptedData)
}

// DecryptWithPublicKey decrypts the encryptedData using the publicKey/privateKey pair and returns the plain text. The publicKey and privateKey must both belong to the recipient - this method only decrypts anonymous messages. You probably want to use PublicKeyDecrypt instead, unless you know what you're doing.
func DecryptWithPublicKey(publicKey []byte, privateKey []byte, encryptedData []byte) ([]byte, error) {
	return box.DecryptWithPublicKey(publicKey, privateKey, encryptedData)
}
