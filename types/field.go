package types

import (
	"time"
)

// Encrypted represents a value that can be encrypted or plaintext
type FieldEncrypted struct {
	Version    uint32    `json:"version,omitempty" bson:"version,omitempty"`       // DEK version used for encryption
	Ciphertext string    `json:"ciphertext,omitempty" bson:"ciphertext,omitempty"` // Base64 encoded encrypted value
	IV         string    `json:"iv,omitempty" bson:"iv,omitempty"`                 // Base64 encoded initialization vector
	Plaintext  string    `json:"plaintext,omitempty" bson:"plaintext,omitempty"`   // Original unencrypted value
	SearchHash string    `json:"searchHash,omitempty" bson:"searchHash,omitempty"` // Optional Base64 encoded hash for searching
	UpdatedAt  time.Time `json:"updatedAt" bson:"updatedAt"`                       // Last update timestamp
}

// FieldStats holds statistics about field encryption operations
type FieldStats struct {
	TotalEncrypts   uint64    `json:"totalEncrypts" bson:"totalEncrypts"`
	TotalDecrypts   uint64    `json:"totalDecrypts" bson:"totalDecrypts"`
	LastEncryptTime time.Time `json:"lastEncryptTime" bson:"lastEncryptTime"`
	LastDecryptTime time.Time `json:"lastDecryptTime" bson:"lastDecryptTime"`
	LastOpTime      time.Time `json:"lastOpTime" bson:"lastOpTime"`
}
