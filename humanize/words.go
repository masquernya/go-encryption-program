package humanize

import (
	_ "embed"
	"errors"
	"strings"
)

//go:embed words.txt
var words string

var wordsArray []string

func GetWord(b byte) string {
	if wordsArray == nil {
		wordsArray = strings.Split(words, "\n")
	}
	return wordsArray[b]
}

func GetByte(s string) byte {
	if wordsArray == nil {
		wordsArray = strings.Split(words, "\n")
	}
	for i, a := range wordsArray {
		if a == s {
			return byte(i)
		}
	}
	panic(errors.New("unknown word: " + s))
}
