package main

import (
	"encoding/base64"
	"fmt"
	"github.com/masquernya/go-encryption-program/encryption"
	"io"
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

		file, err := os.Open(os.Args[3])
		if err != nil {
			panic(err)
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			panic(err)
		}
		bufferSize := 1024 * 16
		fileSize := stat.Size()
		// Max buffer size 128MB
		if fileSize >= 1024*1024*128 {
			bufferSize = 1024 * 1024 * 128
		} else {
			bufferSize = int(fileSize)
		}
		savePath := os.Args[3] + ".enc"
		saveFile, err := os.OpenFile(savePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			panic(err)
		}
		defer saveFile.Close()

		encryptor := encryption.NewEncryptReaderWithBufferSize(publicKey, file, bufferSize)
		_, err = io.Copy(saveFile, encryptor)
		if err != nil {
			panic(err)
			return
		}
		fmt.Println("File encrypted and saved to " + savePath)
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

		file, err := os.Open(os.Args[3])
		if err != nil {
			panic(err)
		}
		defer file.Close()

		outPath := os.Args[3] + ".dec"
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			panic(err)
		}

		decryptor := encryption.NewDecryptReader(publicKey, privateKey, file)
		_, err = io.Copy(outFile, decryptor)
		if err != nil {
			panic(err)
		}
		fmt.Println("File decrypted and saved to " + outPath)
	} else {
		printHelp()
	}
}
