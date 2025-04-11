package types

import (
	"time"
)

// ProviderType represents the type of KMS provider
type ProviderType string

const (
	ProviderAWS   ProviderType = "aws"
	ProviderAzure ProviderType = "azure"
	ProviderGCP   ProviderType = "gcp"
	ProviderVault ProviderType = "vault"
)

// KMSCredentials represents KMS provider credentials
type KMSCredentials struct {
	// AWS credentials
	AccessKeyID     string `json:"accessKeyId,omitempty" bson:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty" bson:"secretAccessKey,omitempty"`
	SessionToken    string `json:"sessionToken,omitempty" bson:"sessionToken,omitempty"`

	// Azure credentials
	TenantID     string `json:"tenantId,omitempty" bson:"tenantId,omitempty"`
	ClientID     string `json:"clientId,omitempty" bson:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty" bson:"clientSecret,omitempty"`

	// GCP credentials
	CredentialsJSON string `json:"credentialsJson,omitempty" bson:"credentialsJson,omitempty"`

	// Vault credentials
	Token string `json:"token,omitempty" bson:"token,omitempty"`
}

// EncryptionConfig represents the encryption service configuration
type EncryptionConfig struct {
	Enabled      bool            `json:"enabled" bson:"enabled"`
	Provider     ProviderType    `json:"provider" bson:"provider"`
	KeyID        string          `json:"keyId" bson:"keyId"`
	Region       string          `json:"region,omitempty" bson:"region,omitempty"`
	KeyRing      string          `json:"keyRing,omitempty" bson:"keyRing,omitempty"`
	VaultAddress string          `json:"vaultAddress,omitempty" bson:"vaultAddress,omitempty"`
	VaultMount   string          `json:"vaultMount,omitempty" bson:"vaultMount,omitempty"`
	Credentials  *KMSCredentials `json:"credentials,omitempty" bson:"credentials,omitempty"`
	Cache        CacheConfig     `json:"cache" bson:"cache"`
	AuditLog     AuditLogConfig  `json:"auditLog" bson:"auditLog"`
	RotateAfter  time.Duration   `json:"rotateAfter" bson:"rotateAfter"`
	CreatedAt    time.Time       `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time       `json:"updatedAt" bson:"updatedAt"`
}

// EncryptionProcessStatusSummary represents a summary status of an encryption process, suitable for API responses.
type EncryptionProcessStatusSummary struct {
	Total     int64   `json:"total" bson:"total"`
	Processed int64   `json:"processed" bson:"processed"`
	Failed    int64   `json:"failed" bson:"failed"`
	Percent   float64 `json:"percent" bson:"percent"` // Calculated value
	Status    string  `json:"status" bson:"status"`
	Error     string  `json:"error,omitempty" bson:"error,omitempty"`
}

// EncryptionProcessDocument represents the full structure stored in the 'encryptionProcesses' collection.
type EncryptionProcessDocument struct {
	ID             string    `bson:"_id" json:"id"`
	OrganizationID string    `bson:"organizationId,omitempty" json:"organizationId,omitempty"` // Optional
	Scope          string    `bson:"scope,omitempty" json:"scope,omitempty"`                   // "system" or "organization"
	Operation      string    `bson:"operation" json:"operation"`                               // "encryption", "decryption", "reencryption"
	Status         string    `bson:"status" json:"status"`                                     // e.g., "starting", "processing", "completed", "failed", "completed_with_errors"
	Processed      int64     `bson:"processed" json:"processed"`
	Failed         int64     `bson:"failed" json:"failed"`
	Total          int64     `bson:"total" json:"total"`
	Progress       float64   `bson:"progress" json:"progress"` // Stored progress percentage
	StartedAt      time.Time `bson:"startedAt" json:"startedAt"`
	UpdatedAt      time.Time `bson:"updatedAt" json:"updatedAt"`
	CompletedAt    time.Time `bson:"completedAt,omitempty" json:"completedAt,omitempty"`
	IsProcessing   bool      `bson:"isProcessing" json:"isProcessing"` // Flag indicating active processing
	IsCompleted    bool      `bson:"isCompleted" json:"isCompleted"`   // Flag indicating completion
	IsFailed       bool      `bson:"isFailed" json:"isFailed"`         // Flag indicating failure
	Error          string    `bson:"error,omitempty" json:"error,omitempty"`
}

// AuditLogConfig represents the audit log configuration
type AuditLogConfig struct {
	Enabled bool   `json:"enabled" bson:"enabled"`
	Type    string `json:"type" bson:"type"`
}
