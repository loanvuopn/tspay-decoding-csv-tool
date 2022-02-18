package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"fujitech.com/tool/csv/pkg/gpg"
)

func main() {
	fmt.Println("=== Start function ===")

	// Read csv input file
	fileName := "COUPON" // example
	csv, err := ioutil.ReadFile("inputs/" + fileName)
	if err != nil {
		fmt.Printf("Can not read csv file: %s", err)
		return
	}
	csvBytes := bytes.NewBuffer(csv)

	// Initial GPG
	bobGPGPrivKeyPath, _ := filepath.Abs("./keys/gpg_bob/gpg.asc")
	gpg := gpg.GPG{
		PrivateKeyPath: bobGPGPrivKeyPath,
		Passphrase:     []byte("passphrase"),
	}

	// Decoding
	contentFile, err := gpg.Decrypt(csvBytes)
	if err != nil {
		fmt.Printf("Failed to decrypt content of file: %s", err)
		return
	}

	// Write csv
	fileDecrypted, err := os.Create("outputs/" + fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s", err)
		return
	}

	_, err = fileDecrypted.Write(contentFile.Bytes())
	if err != nil {
		fmt.Printf("Failed to write file: %s", err)
	}

	fmt.Println("\nFile decryption successful")
	fmt.Println("\n=== End function ===")

}
