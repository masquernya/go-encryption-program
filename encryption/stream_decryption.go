package encryption

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"io"
	"strconv"
)

type StreamDecryption struct {
	DataProvider io.Reader

	// Current position of the buff.
	i int
	// Size of encryption chunks.
	bufferSize int
	// Buffer of decrypted data
	buff []byte
	// Buffer of encrypted data
	encryptedBuff []byte
	privateKey    []byte
	publicKey     []byte
	didReadHeader bool
}

func readAtLeastOrEof(r io.Reader, dest []byte) (int, error) {
	totalN := 0
	for {
		n, err := r.Read(dest[totalN:])
		totalN += n
		if err == io.EOF {
			return totalN, nil
		}
		if err != nil {
			return 0, err
		}
		if totalN >= len(dest) {
			return totalN, nil
		}
	}
}

func (s *StreamDecryption) readHeader() error {
	// 4 bytes for buffer size
	s.buff = make([]byte, 4+len(MagicBytesVersion1))
	if _, err := readAtLeastOrEof(s.DataProvider, s.buff); err != nil {
		return errors.New("error reading header: " + err.Error())
	}
	// We only support MagicBytesVersion1. New versions should add header support here.
	if string(s.buff[:len(MagicBytesVersion1)]) != MagicBytesVersion1 {
		return errors.New("invalid encryption header")
	}
	// Determine buff size.
	s.bufferSize = int(binary.BigEndian.Uint32(s.buff[len(MagicBytesVersion1):]))
	// Right now, up to 128MB is recommended, but we'll allow up to 1GB.
	if s.bufferSize < 1 || s.bufferSize > 1024*1024*1024 {
		return errors.New("invalid decryption buffer size: " + strconv.Itoa(s.bufferSize))
	}
	// Reset buff since there's nothing left to read.
	s.buff = nil
	return nil
}

func (s *StreamDecryption) Read(p []byte) (int, error) {
	// Read public key
	if s.publicKey == nil {
		// get public key from private key
		keyData, err := ecdh.X25519().NewPrivateKey(s.privateKey)
		if err != nil {
			return 0, err
		}
		s.publicKey = keyData.PublicKey().Bytes()
	}

	// Read header
	if !s.didReadHeader {
		if err := s.readHeader(); err != nil {
			return 0, err
		}
		s.didReadHeader = true
	}
	// If our previous decryption still has data left, send that
	if len(s.buff) != 0 && len(s.buff) > s.i {
		n := copy(p, s.buff[s.i:])
		s.i += n
		return n, nil
	}

	// We need to read and decrypt data. Reset i.
	s.i = 0
	if s.encryptedBuff == nil {
		s.encryptedBuff = make([]byte, s.bufferSize+box.AnonymousOverhead)
	}
	toDecryptLen, err := readAtLeastOrEof(s.DataProvider, s.encryptedBuff)
	if err != nil {
		return 0, err
	}
	if toDecryptLen == 0 {
		return 0, io.EOF
	}
	// Read size can be smaller than bufferSize if we're on the last chunk.
	if toDecryptLen < s.bufferSize {
		s.encryptedBuff = s.encryptedBuff[0:toDecryptLen]
	}
	s.buff, err = DecryptWithPublicKey(s.publicKey, s.privateKey, s.encryptedBuff)
	if err != nil {
		return 0, err
	}
	n := copy(p, s.buff[s.i:])
	s.i += n
	return n, nil
}

func NewDecryptReader(privateKey []byte, data io.Reader) io.Reader {
	s := &StreamDecryption{
		DataProvider: data,
		privateKey:   privateKey,
	}
	return s
}
