package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
)

func main() {
	// check if keypair.txt exists
	if _, err := os.Stat("keypair.txt"); os.IsNotExist(err) {
		fmt.Println("keypair.txt does not exist. Would you like to create one now? y/n")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) == "y" {
			createKeypair()
		} else {
			fmt.Println("Exiting...")
			return
		}
	}

	// Read the keypair from keypair.txt
	data, err := os.ReadFile("keypair.txt")
	if err != nil {
		fmt.Println("Error reading keypair.txt:", err)
		return
	}
	keypair := string(data)
	var privkey, pubkey []byte

	if len(keypair) == 128 {
		// Split the keypair into private and public keys
		privkeyHex := keypair[:64]
		pubkeyHex := keypair[64:]
		privkey, err = hex.DecodeString(privkeyHex)
		if err != nil {
			fmt.Println("Error decoding private key:", err)
			return
		}
		pubkey, err = hex.DecodeString(pubkeyHex)
		if err != nil {
			fmt.Println("Error decoding public key:", err)
			return
		}

		// A DoltCoin address is the tuple ["D", pubkey, checksum]
		// payload is D + pubkey
		payload := append([]byte{3 << 3}, pubkey...)
		checksum := calcChecksum(payload)
		address := append(payload, checksum...)
		addressBase32 := base32.StdEncoding.EncodeToString(address)

		fmt.Println("DoltCoin address:", addressBase32)
		fmt.Println("Private key:", hex.EncodeToString(privkey))
		fmt.Println("Public key:", hex.EncodeToString(pubkey))

	} else {
		fmt.Println("Invalid keypair.txt format")
	}

}

// createKeypair creates a new keypair and saves it to keypair.txt
func createKeypair() {
	// Generate a new ed25519 keypair
	_, privkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating keypair:", err)
		return
	}

	// Save the keypair to keypair.txt
	keypair := hex.EncodeToString(privkey)
	err = os.WriteFile("keypair.txt", []byte(keypair), 0644)
	if err != nil {
		fmt.Println("Error creating keypair:", err)
		return
	}

	fmt.Println("Keypair created and saved to keypair.txt")
}

func calcChecksum(payload []byte) []byte {
	crcTable := crc32.MakeTable(crc32.Castagnoli)
	checksum := crc32.Checksum(payload, crcTable)
	checksumBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(checksumBytes, uint16(checksum))
	return checksumBytes
}
