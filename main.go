package main

import (
	"crypto/aes"
	"fmt"
	"golang.org/x/net/icmp"
	"log"
)

type fileData struct {
	Name           string
	Extension      string
	ReceivedChunks int
	TotalChunks    int
	Bytes          []byte
}

var (
	// Index: file ID, value: fileData
	files map[string]*fileData = make(map[string]*fileData, 0)
)

func main() {
	fmt.Println("[i] Opening ICMP socket")

	// Open socket for ICMP packets
	packetConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("[!] Failed to open ICMP socket [%v]\n", err)
	}

	// Defer socket closure
	defer func(packetConn *icmp.PacketConn) {
		err := packetConn.Close()
		if err != nil {

		}
	}(packetConn)

	for {
		// Create read buffer for packet data
		packetBuf := make([]byte, 1500)

		// Read into buffer
		_, _, err := packetConn.ReadFrom(packetBuf)
		if err != nil {
			log.Printf("[!] Failed to read ICMP packet [%v]\n", err)
			continue
		}
		// Ignore headers
		data := packetBuf[28:]
		// Fetch file ID
		fileID := data[:32]

		// Check if file exists in map if not, add it
		if file, exists := files[string(fileID)]; exists {
			// Is this our last chunk?
			file.ReceivedChunks += 1
			if file.ReceivedChunks == file.TotalChunks {
				// Expect padding

			}
		} else {

		}

	}
}

func aesDecrypt(encryptedData, key []byte) ([]byte, error) {
	// Create new cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Ensure data is aligned to block size
	if (len(encryptedData) % aes.BlockSize) != 0 {
		return nil, fmt.Errorf("encrypted data is not aligned to block size")
	}

	decrypted := make([]byte, len(encryptedData))
	for i := 0; i < len(encryptedData); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], encryptedData[i:i+aes.BlockSize])

	}

	return decrypted, nil
}

func pkcsDePad(data []byte, blockSize int) ([]byte, error) {
	// Validate block size
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid blocksize")
	}

	// Validate PKCS7 data
	if (len(data)%blockSize) != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid PKCS7 data (not padded)")
	}

	// Calculate padding based on length
	padding := data[len(data)-1]
	padLen := int(padding)
	if padLen > blockSize || padLen == 0 {
		return nil, fmt.Errorf("invalid padding found")
	}

	// Verify padding bytes
	for _, b := range data[len(data)-padLen:] {
		if b != padding {
			return nil, fmt.Errorf("invalid padding found")
		}
	}
	return data[:len(data)-padLen], nil
}

//func parseMetadata(data []byte) (*fileData, error) {
//
//}
