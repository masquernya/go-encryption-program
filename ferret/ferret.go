// Package ferret provides an api for encrypting and decrypting files.
package ferret

import (
	"github.com/masquernya/go-encryption-program/encryption"
	"io"
	"os"
)

// EncryptFile encrypts the inFilePath using publicKey and writes it to outFilePath, truncating the outFilePath if it exists.
func EncryptFile(inFilePath string, outFilePath string, publicKey []byte) error {
	file, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}
	bufferSize := 1024 * 16
	fileSize := stat.Size()
	// Max buffer size 128MB
	if fileSize > 1024*1024*128 {
		bufferSize = 1024 * 1024 * 128
	} else {
		bufferSize = int(fileSize)
	}
	saveFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer saveFile.Close()

	encryptor := encryption.NewEncryptReaderWithBufferSize(publicKey, file, bufferSize)
	_, err = io.Copy(saveFile, encryptor)
	if err != nil {
		return err
	}
	return nil
}

// DecryptFile decrypts the inFilePath to outFilePath using the privateKey, truncating outFilePath if it exists.
func DecryptFile(inFilePath string, outFilePath string, privateKey []byte) error {
	file, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	decryptor := encryption.NewDecryptReader(privateKey, file)
	_, err = io.Copy(outFile, decryptor)
	if err != nil {
		return err
	}
	return nil
}
