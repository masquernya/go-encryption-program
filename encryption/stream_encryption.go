package encryption

import (
	crypto_ran "crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/nacl/box"
	"io"
)

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
	toEncryptLen, err := readAtLeastOrEof(s.DataProvider, s.unencryptedBuff)
	if err != nil {
		return 0, err
	}
	if toEncryptLen == 0 {
		return 0, io.EOF
	}
	if toEncryptLen < s.bufferSize {
		s.unencryptedBuff = s.unencryptedBuff[0:toEncryptLen]
	}
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
