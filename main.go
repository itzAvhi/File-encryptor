package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func deriveKeyFromPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {

		return nil, fmt.Errorf("failed to derive key from password: %w", err)
	}
	return hashedPassword, nil
}

func main() {
	modePtr := flag.String("mode", "", "Select a mode either 'encrypt' or 'decrypt' [required]")
	inputPtr := flag.String("input", "", "Select an input file [required]")
	outputPtr := flag.String("output", "", "Select an output file [required]")
	passwordPtr := flag.String("password", "", "A master password is required [required]") // Added [required] for clarity

	flag.Parse()

	mode := *modePtr
	input := *inputPtr
	output := *outputPtr
	password := *passwordPtr

	if mode == "" || input == "" || output == "" || password == "" {
		fmt.Println("Error: All flags (-mode, -input, -output, -password) are required.")
		flag.Usage()
		os.Exit(1)
	}

	derivedKey, err := deriveKeyFromPassword(password)
	if err != nil {
		log.Fatalf("Error deriving key: %v", err)
	}

	fmt.Println("Key derivation successful.")
	fmt.Printf("Derived Key (first 16 bytes hex): %x...)", derivedKey[:16])

	fmt.Printf("Mode: %s", mode)
	fmt.Printf("Input File: %s", input)
	fmt.Printf("Output File: %s", output)
	fmt.Printf("Password: %s", password)
}
