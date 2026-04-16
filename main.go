package main

import (
	"crypto/aes"
	"crypto/cipher"
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

func generateNonce(gcm cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	_, err := rand.Read(nonce)
	return nonce, err
}

func encrypt(filePath, password string) error {
	// Read the file
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Generate salt
	salt, err := generateSalt()
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	// Derive key from password and salt
	key := deriveKey(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	// Create GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	// Generate nonce
	nonce, err := generateNonce(gcm)
	if err != nil {
		return fmt.Errorf("error generating nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Create encrypted file with .enc extension
	outputPath := filePath + ".enc"
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer outputFile.Close()

	// Write salt (first 16 bytes) followed by ciphertext (nonce + encrypted data)
	if _, err := outputFile.Write(salt); err != nil {
		return fmt.Errorf("error writing salt: %w", err)
	}

	if _, err := outputFile.Write(ciphertext); err != nil {
		return fmt.Errorf("error writing ciphertext: %w", err)
	}

	fmt.Printf("File encrypted successfully: %s -> %s\n", filePath, outputPath)
	return nil
}

func decrypt(filePath, password string) error {
	// Read the encrypted file
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Extract salt (first 16 bytes)
	if len(encryptedData) < 16 {
		return fmt.Errorf("invalid encrypted file format")
	}
	salt := encryptedData[:16]
	ciphertext := encryptedData[16:]

	// Derive key from password and salt
	key := deriveKey(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	// Create GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	// Extract nonce (first NonceSize bytes of ciphertext)
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("invalid encrypted file format")
	}

	nonce := ciphertext[:nonceSize]
	encryptedContent := ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, encryptedContent, nil)
	if err != nil {
		return fmt.Errorf("error decrypting file: %w", err)
	}

	// Remove .enc extension for output filename
	outputPath := filePath
	if len(filePath) > 4 && filePath[len(filePath)-4:] == ".enc" {
		outputPath = filePath[:len(filePath)-4]
	} else {
		outputPath = filePath + ".dec"
	}

	// Write decrypted content
	err = os.WriteFile(outputPath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("error writing decrypted file: %w", err)
	}

	fmt.Printf("File decrypted successfully: %s -> %s\n", filePath, outputPath)
	return nil
}

func main() {
	mode := flag.String("mode", "", "Operation mode: 'encrypt' or 'decrypt'")
	filePath := flag.String("file", "", "Path to the file")
	password := flag.String("pass", "", "Password for encryption/decryption")

	flag.Parse()

	if *mode == "" || *filePath == "" || *password == "" {
		fmt.Println("Usage: -mode [encrypt/decrypt] -file [path] -pass [password]")
		fmt.Println("  -mode    : 'encrypt' or 'decrypt'")
		fmt.Println("  -file    : Path to the file to process")
		fmt.Println("  -pass    : Password for encryption/decryption")
		os.Exit(1)
	}

	// Route the logic based on the mode
	switch *mode {
	case "encrypt":
		err := encrypt(*filePath, *password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	case "decrypt":
		err := decrypt(*filePath, *password)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'.")
		os.Exit(1)
	}
}
