package encryption

import (
	crypto_ran "crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"io"
	"strconv"
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

const defaultBufferSize int = 1024 * 16 // 128mb
type StreamEncryption struct {
	DataProvider io.Reader

	i               int
	buff            []byte
	unencryptedBuff []byte
	publicKey       []byte

	didSendHeader bool
	bufferSize    int
}

func (s *StreamEncryption) Read(p []byte) (int, error) {
	if !s.didSendHeader {
		s.buff = make([]byte, 4+len(MagicBytesVersion1))
		copy(s.buff, MagicBytesVersion1)
		binary.BigEndian.PutUint32(s.buff[len(MagicBytesVersion1):], uint32(s.bufferSize))
		s.didSendHeader = true
	}
	if len(s.buff) != 0 && len(s.buff) > s.i {
		n := copy(p, s.buff[s.i:])
		s.i += n
		return n, nil
	}

	s.i = 0
	if s.unencryptedBuff == nil {
		s.unencryptedBuff = make([]byte, s.bufferSize)
	}
	toEncryptLen := readAtLeastOrEof(s.DataProvider, s.unencryptedBuff)
	if toEncryptLen == 0 {
		return 0, io.EOF
	}
	if toEncryptLen < s.bufferSize {
		s.unencryptedBuff = s.unencryptedBuff[0:toEncryptLen]
	}
	var err error
	s.buff, err = box.SealAnonymous(nil, s.unencryptedBuff[:toEncryptLen], (*[32]byte)(s.publicKey), crypto_ran.Reader)
	if err != nil {
		return 0, err
	}
	s.unencryptedBuff = nil
	n := copy(p, s.buff[s.i:])
	s.i += n
	return n, nil
}

func NewEncryptReader(publicKey []byte, data io.Reader) io.Reader {
	s := &StreamEncryption{
		DataProvider: data,
		publicKey:    publicKey,
		bufferSize:   defaultBufferSize,
	}
	return s
}

func NewEncryptReaderWithBufferSize(publicKey []byte, data io.Reader, bufferSize int) io.Reader {
	s := &StreamEncryption{
		DataProvider: data,
		publicKey:    publicKey,
		bufferSize:   bufferSize,
	}
	return s
}

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

func readAtLeastOrEof(r io.Reader, dest []byte) int {
	totalN := 0
	for {
		n, err := r.Read(dest[totalN:])
		totalN += n
		if err == io.EOF {
			return totalN
		}
		if err != nil {
			panic(err)
		}
		if totalN >= len(dest) {
			return totalN
		}
	}
}

func (s *StreamDecryption) Read(p []byte) (int, error) {
	if !s.didReadHeader {
		s.buff = make([]byte, 4+len(MagicBytesVersion1))
		readAtLeastOrEof(s.DataProvider, s.buff)
		if string(s.buff[:len(MagicBytesVersion1)]) != MagicBytesVersion1 {
			return 0, errors.New("invalid encryption header")
		}
		s.bufferSize = int(binary.BigEndian.Uint32(s.buff[len(MagicBytesVersion1):]))
		if s.bufferSize < 1024 || s.bufferSize > 1024*1024*1024 {
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
	toEncryptLen := readAtLeastOrEof(s.DataProvider, s.encryptedBuff)
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

func NewDecryptReader(publicKey []byte, privateKey []byte, data io.Reader) io.Reader {
	s := &StreamDecryption{
		DataProvider: data,
		publicKey:    publicKey,
		privateKey:   privateKey,
	}
	return s
}
