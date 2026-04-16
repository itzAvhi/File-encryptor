package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// Define the flags
	mode := flag.String("mode", "", "Operation mode: 'encrypt' or 'decrypt'")
	filePath := flag.String("file", "", "Path to the file")
	password := flag.String("pass", "", "Password for encryption/decryption")

	flag.Parse()

	// Validate inputs
	if *mode == "" || *filePath == "" || *password == "" {
		fmt.Println("Usage: -mode [encrypt/decrypt] -file [path] -pass [password]")
		os.Exit(1)
	}

	// Route the logic based on the mode
	switch *mode {
	case "encrypt":
		fmt.Printf("Encrypting file: %s\n", *filePath)
		// Call your encrypt function here
	case "decrypt":
		fmt.Printf("Decrypting file: %s\n", *filePath)
		// Call your decrypt function here
	default:
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'.")
	}
}
