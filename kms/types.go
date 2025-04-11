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

// ProviderType represents the type of KMS provider
type ProviderType string

// Provider type constants
const (
	ProviderAWS   ProviderType = "aws"
	ProviderAzure ProviderType = "azure"
	ProviderGCP   ProviderType = "gcp"
	ProviderVault ProviderType = "vault"
)

// Config represents the internal KMS provider configuration
type Config struct {
	Type         types.ProviderType     `json:"type" bson:"type"`
	KeyID        string                 `json:"keyId" bson:"keyId"`
	Region       string                 `json:"region,omitempty" bson:"region,omitempty"`
	KeyRing      string                 `json:"keyRing,omitempty" bson:"keyRing,omitempty"`
	Credentials  map[string]interface{} `json:"credentials,omitempty" bson:"credentials,omitempty"`
	VaultAddress string                 `json:"vaultAddress,omitempty" bson:"vaultAddress,omitempty"`
	VaultMount   string                 `json:"vaultMount,omitempty" bson:"vaultMount,omitempty"`
}
