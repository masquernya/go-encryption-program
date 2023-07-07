package main

import (
	"encoding/base64"
	"fmt"
	"github.com/masquernya/go-encryption-program/encryption"
	"github.com/masquernya/go-encryption-program/ferret"
	"os"
)

func printHelp() {
	fmt.Println("OwO1 Encryption Standard. Essentially NaCL box with chunk support.")
	fmt.Println("Commands:")
	fmt.Println("  help                           print help command")
	fmt.Println("  encrypt <publickey> <filepath> encrypt file with public key, saving to <filepath>.enc")
	fmt.Println("  decrypt <publickey> <filepath> decrypt file, saving to <filepath>.dec. private key is read from the PRIVATE_KEY environmental variable.")
	fmt.Println("  generatekey                    generate public and private key, then print it to the terminal")
	os.Exit(0)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" {
		printHelp()
	}

	if os.Args[1] == "generatekey" {
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
	} else if os.Args[1] == "encrypt" {
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
	} else if os.Args[1] == "decrypt" {
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
	} else {
		printHelp()
	}
}
