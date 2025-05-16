package kms

import (
	"context"

	"github.com/root-sector/multi-payment-gateway-module-encryption/types"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Provider represents a KMS provider
type Provider interface {
	// GetWrapper returns the underlying KMS wrapper
	GetWrapper() wrapping.Wrapper

	// Test performs a test encryption/decryption
	Test(ctx context.Context) error

	// HealthCheck performs a comprehensive health check
	HealthCheck(ctx context.Context) error

	// GetLastHealthCheckError returns the last health check error
	GetLastHealthCheckError() error
}

// --- Provider Specific Config Structs ---

// AWSConfig holds configuration specific to AWS KMS
type AWSConfig struct {
	KeyID       string                 `json:"keyId" bson:"keyId"` // Key ARN
	Region      string                 `json:"region" bson:"region"`
	Credentials map[string]interface{} `json:"credentials,omitempty" bson:"credentials,omitempty"` // accessKeyId, secretAccessKey, sessionToken (optional)
}

// AzureConfig holds configuration specific to Azure Key Vault
type AzureConfig struct {
	KeyID        string                 `json:"keyId" bson:"keyId"`                                 // Key Identifier (URL)
	VaultAddress string                 `json:"vaultAddress" bson:"vaultAddress"`                   // e.g., https://myvault.vault.azure.net
	Credentials  map[string]interface{} `json:"credentials,omitempty" bson:"credentials,omitempty"` // tenantId, clientId, clientSecret
}

// GCPConfig holds configuration specific to Google Cloud KMS
type GCPConfig struct {
	ResourceName string                 `json:"resourceName" bson:"resourceName"`                   // Full KMS key resource name (projects/.../cryptoKeys/...)
	Credentials  map[string]interface{} `json:"credentials,omitempty" bson:"credentials,omitempty"` // credentialsJson (content of the SA key file)
}

// VaultConfig holds configuration specific to HashiCorp Vault Transit engine
type VaultConfig struct {
	KeyID        string                 `json:"keyId" bson:"keyId"`                                 // Key name within Vault Transit
	VaultAddress string                 `json:"vaultAddress" bson:"vaultAddress"`                   // e.g., https://vault.example.com:8200
	VaultMount   string                 `json:"vaultMount,omitempty" bson:"vaultMount,omitempty"`   // Mount path (default: transit)
	Credentials  map[string]interface{} `json:"credentials,omitempty" bson:"credentials,omitempty"` // token
}

// --- Main Config Struct ---

// Config represents the KMS provider configuration, holding the type
// and a pointer to the relevant provider-specific configuration.
// It also includes direct fields for simpler AEAD provider configuration.
type Config struct {
	Type          types.ProviderType `json:"type" bson:"type"`
	AWS           *AWSConfig         `json:"aws,omitempty" bson:"aws,omitempty"`
	Azure         *AzureConfig       `json:"azure,omitempty" bson:"azure,omitempty"`
	GCP           *GCPConfig         `json:"gcp,omitempty" bson:"gcp,omitempty"`
	Vault         *VaultConfig       `json:"vault,omitempty" bson:"vault,omitempty"`
	AeadKeyID     string             `json:"aeadKeyId,omitempty" bson:"aeadKeyId,omitempty"`         // Added for AEAD
	AeadKeyBase64 string             `json:"aeadKeyBase64,omitempty" bson:"aeadKeyBase64,omitempty"` // Added for AEAD
}
