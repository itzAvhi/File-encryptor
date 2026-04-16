package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"

	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keySize    = 32 // 256-bit key for AES-256
	saltSize   = 16
	iterations = 100000
)

// deriveKeyFromPassword generates a 256-bit key from a password using PBKDF2
func deriveKeyFromPassword(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

// encrypt reads a file, encrypts it, and writes to output
func encrypt(inputFile, outputFile, password string) error {
	// Read input file
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key := deriveKeyFromPassword(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode (authenticated encryption)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Write output file: salt + nonce + ciphertext
	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer output.Close()

	if _, err := output.Write(salt); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}
	if _, err := output.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}
	if _, err := output.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return nil
}

// decrypt reads an encrypted file and writes decrypted content to output
func decrypt(inputFile, outputFile, password string) error {
	// Read encrypted file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Extract salt, nonce, and ciphertext
	if len(data) < saltSize {
		return fmt.Errorf("invalid encrypted file: too small")
	}

	salt := data[:saltSize]
	data = data[saltSize:]

	// Derive key from password
	key := deriveKeyFromPassword(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("invalid encrypted file: nonce missing")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	// Write output file
	if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

func main() {
	// Define command-line flags
	mode := flag.String("mode", "", "encrypt or decrypt")
	input := flag.String("input", "", "input file path")
	output := flag.String("output", "", "output file path")
	password := flag.String("password", "", "password for encryption/decryption")

	flag.Parse()

	// Validate flags
	if *mode == "" || *input == "" || *output == "" || *password == "" {
		fmt.Println("Usage: go run main.go -mode encrypt|decrypt -input file -output file -password pass")
		os.Exit(1)
	}

	// Execute encrypt or decrypt
	var err error
	if *mode == "encrypt" {
		fmt.Println("Encrypting file...")
		err = encrypt(*input, *output, *password)
	} else if *mode == "decrypt" {
		fmt.Println("Decrypting file...")
		err = decrypt(*input, *output, *password)
	} else {
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'")
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Println("✓ Operation completed successfully!")
}
