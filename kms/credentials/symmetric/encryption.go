package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/interfaces"
)

// encryption implements the interfaces.SymmetricEncryptor interface
type encryption struct {
	key []byte
}

// encryptionPrefix is used to identify encrypted data
const encryptionPrefix = "ENC["

// NewEncryption creates a new AES-GCM encryptor
func NewEncryption(key []byte) (interfaces.SymmetricEncryptor, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("encryption key must be at least 32 bytes")
	}

	// Always use exactly 32 bytes for AES-256
	key = key[:32]

	// Validate key entropy
	if !validateKeyEntropy(key) {
		return nil, fmt.Errorf("key has insufficient entropy")
	}

	return &encryption{key: key}, nil
}

// validateKeyEntropy performs a basic entropy check on the key
func validateKeyEntropy(key []byte) bool {
	// Count unique bytes
	uniqueBytes := make(map[byte]bool)
	for _, b := range key {
		uniqueBytes[b] = true
	}

	// Require at least 16 unique bytes in the key
	return len(uniqueBytes) >= 16
}

// isEncrypted checks if a string is already encrypted by checking for our prefix
func isEncrypted(s string) bool {
	return strings.HasPrefix(s, encryptionPrefix)
}

// Encrypt encrypts data using AES-256-GCM
func (e *encryption) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	// Check if the input is already encrypted
	if isEncrypted(plaintext) {
		return plaintext, nil
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64 and add prefix
	encoded := encryptionPrefix + base64.URLEncoding.EncodeToString(ciphertext) + "]"

	return encoded, nil
}

// Decrypt decrypts data using AES-256-GCM
func (e *encryption) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", fmt.Errorf("ciphertext cannot be empty")
	}

	// Check if the input is actually encrypted
	if !isEncrypted(ciphertext) {
		return ciphertext, nil
	}

	// Remove prefix and suffix
	trimmed := strings.TrimPrefix(ciphertext, encryptionPrefix)
	trimmed = strings.TrimSuffix(trimmed, "]")

	// Decode from base64
	decoded, err := base64.URLEncoding.DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(decoded) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := decoded[:nonceSize]
	ciphertextBytes := decoded[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
