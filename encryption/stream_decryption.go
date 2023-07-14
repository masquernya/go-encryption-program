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

	i             int
	bufferSize    int
	buff          []byte
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

func (s *StreamDecryption) Read(p []byte) (int, error) {
	if !s.didReadHeader {
		s.buff = make([]byte, 4+len(MagicBytesVersion1))
		if _, err := readAtLeastOrEof(s.DataProvider, s.buff); err != nil {
			return 0, errors.New("error reading header: " + err.Error())
		}
		if string(s.buff[:len(MagicBytesVersion1)]) != MagicBytesVersion1 {
			return 0, errors.New("invalid encryption header")
		}
		s.bufferSize = int(binary.BigEndian.Uint32(s.buff[len(MagicBytesVersion1):]))
		if s.bufferSize < 1 || s.bufferSize > 1024*1024*1024 {
			return 0, errors.New("invalid decryption buffer size: " + strconv.Itoa(s.bufferSize))
		}
		s.didReadHeader = true
		s.buff = nil
	}
	if len(s.buff) != 0 && len(s.buff) > s.i {
		n := copy(p, s.buff[s.i:])
		s.i += n
		return n, nil
	}

	s.i = 0
	if s.encryptedBuff == nil {
		s.encryptedBuff = make([]byte, s.bufferSize+box.AnonymousOverhead)
	}
	toEncryptLen, err := readAtLeastOrEof(s.DataProvider, s.encryptedBuff)
	if err != nil {
		return 0, err
	}
	if toEncryptLen == 0 {
		return 0, io.EOF
	}
	if toEncryptLen < s.bufferSize {
		s.encryptedBuff = s.encryptedBuff[0:toEncryptLen]
	}
	var ok bool
	s.buff, ok = box.OpenAnonymous(nil, s.encryptedBuff, (*[32]byte)(s.publicKey), (*[32]byte)(s.privateKey))
	if !ok {
		return 0, errors.New("decryption failed")
	}
	n := copy(p, s.buff[s.i:])
	s.i += n
	return n, nil
}

func NewDecryptReader(privateKey []byte, data io.Reader) io.Reader {
	// get public key from private key
	keyData, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	publicKey := keyData.PublicKey().Bytes()

	s := &StreamDecryption{
		DataProvider: data,
		publicKey:    publicKey,
		privateKey:   privateKey,
	}
	return s
}
