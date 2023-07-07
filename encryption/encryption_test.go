package encryption

import (
	"bytes"
	crypto_ran "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"os"
	"runtime"
	"testing"
	"time"
)

func calcHashUsingBuffer(path string, b []byte) []byte {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	originalSh := sha256.New()
	for {
		n, err := file.Read(b)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		originalSh.Write(b[:n])
	}
	return originalSh.Sum(nil)
}

func TestEncryptReaderFile(t *testing.T) {
	var maxMemoryBytes = 1024 * 1024 * 128 // 128MB
	random1gFile := "./test_file_4gb.bin"
	if _, err := os.Stat(random1gFile); os.IsNotExist(err) {
		log.Println("generating random file")
		file, err := os.Create(random1gFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.CopyN(file, crypto_ran.Reader, 1024*1024*1024*4); err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			return
		}
	}
	publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	// Shared buffer for operations.
	b := make([]byte, 1024*16)
	// First, calculate hash of test_file_4gb.bin
	originalHash := calcHashUsingBuffer(random1gFile, b)
	log.Println("Original hash:", base64.StdEncoding.EncodeToString(originalHash))

	// Now do encryption/decryption
	file, err := os.Open(random1gFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	maxMemoryBytes += int(stat.Size() / 8)

	encrypted := NewEncryptReaderWithBufferSize(publicKey, file, 1024*1024*128)
	decrypted := NewDecryptReader(publicKey, privateKey, encrypted) // Feed encrypted straight into decrypted.

	var encryptedSize = 0
	lastPrint := time.Now()
	sh := sha256.New()

	for {
		if time.Since(lastPrint) > time.Second {
			runtime.GC()
			log.Println("encrypted size", encryptedSize, "bytes", float64(encryptedSize)/1024/1024, "MB")
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.Alloc > uint64(maxMemoryBytes) {
				log.Println("memory leak", m.Alloc, "bytes", float64(m.Alloc)/1024/1024, "MB")
				t.Fatal("memory leak")
			}
			lastPrint = time.Now()
		}
		n, err := decrypted.Read(b)
		encryptedSize += n
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		sh.Write(b[:n])
	}
	hash := sh.Sum(nil)
	log.Println("Hash after decryption:", base64.StdEncoding.EncodeToString(hash))
	if !bytes.Equal(hash, originalHash) {
		t.Fatal("hashes do not match")
	}
}

func TestEncryptReader(t *testing.T) {
	reallyBigData := make([]byte, 1024*32) // 32KB
	if _, err := crypto_ran.Read(reallyBigData); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	encryptedBytes := NewEncryptReaderWithBufferSize(publicKey, bytes.NewReader(reallyBigData), 1024*16)
	data, err := io.ReadAll(encryptedBytes)
	if err != nil {
		t.Fatal(err)
	}
	log.Println("data", base64.StdEncoding.EncodeToString(data))
	if len(data) < len(reallyBigData) {
		t.Fatal("wrong size")
	}

	encryptedReader := bytes.NewReader(data)
	decryptedBytes := NewDecryptReader(publicKey, privateKey, encryptedReader)
	decryptedData, err := io.ReadAll(decryptedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(decryptedData) != len(reallyBigData) {
		t.Fatal("different sizes after decryption", len(decryptedData), "vs", len(reallyBigData))
	}
	if !bytes.Equal(decryptedData, reallyBigData) {
		t.Fatal("decrypted data does not match original")
	}
}
