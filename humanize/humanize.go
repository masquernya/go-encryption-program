package humanize

import "strings"

// GetString returns a human-readable string of the bytes.
func GetString(b []byte) string {
	s := ""
	for _, a := range b {
		s += GetWord(a) + " "
	}
	return s
}

// GetBytes returns a byte array from a human-readable string.
func GetBytes(s string) []byte {
	sp := strings.Split(s, " ")
	b := make([]byte, len(sp))
	for i, a := range sp {
		b[i] = GetByte(a)
	}
	return b
}
