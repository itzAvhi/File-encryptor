package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 1000000, 32, sha256.New)
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

func main() {
	mode := flag.String("mode", "", "Operation mode: 'encrypt' or 'decrypt'")
	filePath := flag.String("file", "", "Path to the file")
	password := flag.String("pass", "", "Password for encryption/decryption")

	flag.Parse()

	if *mode == "" || *filePath == "" || *password == "" {
		fmt.Println("Usage: -mode [encrypt/decrypt] -file [path] -pass [password]")
		os.Exit(1)
	}

	// Route the logic based on the mode
	switch *mode {
	case "encrypt":
		fmt.Printf("Encrypting file: %s\n", *filePath)

	case "decrypt":
		fmt.Printf("Decrypting file: %s\n", *filePath)

	default:
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'.")
	}
}
