package main

import (
	"encoding/base64"
	"fmt"
	"github.com/masquernya/go-encryption-program/encryption"
	"github.com/masquernya/go-encryption-program/ferret"
	"os"
	"strings"
	"unicode/utf8"
)

var commands = map[string]struct {
	Arguments   []string
	Description string
}{
	"help": {
		Arguments:   []string{},
		Description: "print this help message",
	},
	"encrypt-file": {
		Arguments:   []string{"<publickey>", "<filepath>"},
		Description: "encrypt file with public key, saving to <filepath>.enc",
	},
	"decrypt-file": {
		Arguments:   []string{"<publickey>", "<filepath>"},
		Description: "decrypt file, saving to <filepath>.dec. private key is read from the PRIVATE_KEY environmental variable.",
	},
	"genkey": {
		Arguments:   []string{},
		Description: "generate public and private key, then print it to the terminal",
	},
	"decrypt-nacl": {
		Arguments:   []string{"<publickey>", "<message>"},
		Description: "decrypt anonymous nacl box message (Base64 encoded) and print it to the terminal. private key is read from the PRIVATE_KEY environmental variable.",
	},
	"encrypt-nacl": {
		Arguments:   []string{"<publickey>", "<message>"},
		Description: "encrypt message with public key and print it to the terminal (Base64 encoded)",
	},
}

func printHelp() {
	fmt.Println("OwO1 Encryption Standard. Essentially NaCL box with chunk support.")
	fmt.Println("Commands:")
	for cmd, data := range commands {
		fmt.Print("\n")
		fmt.Println("" + cmd + " " + strings.Join(data.Arguments, " "))
		fmt.Println("    " + data.Description)
	}
	os.Exit(0)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" {
		printHelp()
	}

	if os.Args[1] == "genkey" {
		publicKey, privateKey, err := encryption.GenerateKeys()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Public Key (Base64):")
		fmt.Println(base64.StdEncoding.EncodeToString(publicKey))
		fmt.Println("Private Key (Base64):")
		fmt.Println(base64.StdEncoding.EncodeToString(privateKey))
		os.Exit(0)
	} else if os.Args[1] == "encrypt-file" {
		if len(os.Args) < 4 {
			printHelp()
		}
		publicKey, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			panic(err)
		}
		inFilePath := os.Args[3]
		outFilePath := inFilePath + ".enc"
		err = ferret.EncryptFile(inFilePath, outFilePath, publicKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("File encrypted and saved to " + outFilePath)
	} else if os.Args[1] == "decrypt-file" {
		if len(os.Args) < 4 {
			printHelp()
		}
		publicKey, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			panic(err)
		}
		privateKeyStr, privateKeyExists := os.LookupEnv("PRIVATE_KEY")
		if !privateKeyExists {
			fmt.Println("Environment variable PRIVATE_KEY not found")
			os.Exit(1)
		}
		privateKey, err := base64.StdEncoding.DecodeString(privateKeyStr)
		if err != nil {
			panic(err)
		}

		inFilePath := os.Args[3]
		outFilePath := inFilePath + ".dec"

		err = ferret.DecryptFile(inFilePath, outFilePath, publicKey, privateKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("File decrypted and saved to " + outFilePath)
	} else if os.Args[1] == "encrypt-nacl" {
		if len(os.Args) < 3 {
			printHelp()
		}
		publicKey, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			panic(err)
		}
		message := os.Args[3]

		encrypted, err := encryption.Encrypt(publicKey, []byte(message))
		if err != nil {
			panic(err)
		}
		fmt.Println("Encrypted message (Base64):")
		fmt.Println(base64.StdEncoding.EncodeToString(encrypted))

	} else if os.Args[1] == "decrypt-nacl" {
		if len(os.Args) < 4 {
			printHelp()
		}
		publicKey, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			panic(err)
		}
		privateKeyStr, privateKeyExists := os.LookupEnv("PRIVATE_KEY")
		if !privateKeyExists {
			fmt.Println("Environment variable PRIVATE_KEY not found")
			os.Exit(1)
		}
		privateKey, err := base64.StdEncoding.DecodeString(privateKeyStr)
		if err != nil {
			panic(err)
		}

		message, err := base64.StdEncoding.DecodeString(os.Args[3])
		if err != nil {
			panic(err)
		}

		decrypted, err := encryption.Decrypt(publicKey, privateKey, message)
		if err != nil {
			panic(err)
		}

		ok := utf8.Valid(decrypted)
		if !ok {
			fmt.Println("Message (Base64):")
			fmt.Println(base64.StdEncoding.EncodeToString(decrypted))
			os.Exit(0)
		}
		fmt.Println("Message:")
		fmt.Println(string(decrypted))
	} else {
		printHelp()
	}
}
