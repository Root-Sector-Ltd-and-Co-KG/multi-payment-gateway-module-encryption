// Package kms provides KMS provider functionality
package kms

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/root-sector/multi-payment-gateway-module-encryption/types"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	awskms "github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	azurekeyvault "github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2"
	gcpckms "github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	transit "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
	"github.com/rs/zerolog"
)

var log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

// provider implements the Provider interface
type provider struct {
	wrapper         wrapping.Wrapper
	lastHealthCheck error
}

// NewProvider creates a new KMS provider based on the configuration
func NewProvider(config Config) (Provider, error) {
	var wrapper wrapping.Wrapper
	var err error

	log.Debug().
		Str("provider", string(config.Type)).
		Str("keyId", config.KeyID).
		Str("region", config.Region).
		Msg("Initializing KMS provider")

	switch config.Type {
	case types.ProviderAWS:
		if err := validateAWSConfig(config); err != nil {
			return nil, fmt.Errorf("invalid AWS KMS configuration: %w", err)
		}
		wrapper, err = createAWSWrapper(config)
	case types.ProviderAzure:
		if err := validateAzureConfig(config); err != nil {
			return nil, fmt.Errorf("invalid Azure Key Vault configuration: %w", err)
		}
		wrapper, err = createAzureWrapper(config)
	case types.ProviderGCP:
		if err := validateGCPConfig(config); err != nil {
			return nil, fmt.Errorf("invalid GCP KMS configuration: %w", err)
		}
		wrapper, err = createGCPWrapper(config)
	case types.ProviderVault:
		if err := validateVaultConfig(config); err != nil {
			return nil, fmt.Errorf("invalid Vault configuration: %w", err)
		}
		wrapper, err = createVaultWrapper(config)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.Type)
	}

	if err != nil {
		log.Error().Err(err).Str("provider", string(config.Type)).Msg("Failed to create KMS provider")
		return nil, fmt.Errorf("failed to create wrapper: %w", err)
	}

	log.Info().
		Str("provider", string(config.Type)).
		Str("keyId", config.KeyID).
		Msg("KMS provider initialized successfully")

	return &provider{
		wrapper:         wrapper,
		lastHealthCheck: nil,
	}, nil
}

// GetWrapper returns the underlying KMS wrapper
func (p *provider) GetWrapper() wrapping.Wrapper {
	return p.wrapper
}

// Test tests the KMS wrapper by performing a test encryption/decryption
func (p *provider) Test(ctx context.Context) error {
	if p.wrapper == nil {
		return fmt.Errorf("wrapper not initialized")
	}

	// Test data
	testData := []byte("test")

	// Try to encrypt
	encrypted, err := p.wrapper.Encrypt(ctx, testData)
	if err != nil {
		return fmt.Errorf("encryption test failed: %w", err)
	}

	// Try to decrypt
	decrypted, err := p.wrapper.Decrypt(ctx, encrypted)
	if err != nil {
		return fmt.Errorf("decryption test failed: %w", err)
	}

	// Verify decrypted data
	if string(decrypted) != string(testData) {
		return fmt.Errorf("decrypted data does not match original")
	}
	return nil
}

// HealthCheck performs a comprehensive health check of the KMS provider
func (p *provider) HealthCheck(ctx context.Context) error {
	// Check if wrapper is initialized
	if p.wrapper == nil {
		return fmt.Errorf("KMS provider not properly initialized: wrapper is nil")
	}

	// Perform encryption/decryption test
	err := p.Test(ctx)
	if err != nil {
		p.lastHealthCheck = fmt.Errorf("KMS provider health check failed: %w", err)
		return p.lastHealthCheck
	}

	p.lastHealthCheck = nil
	return nil
}

// GetLastHealthCheckError returns the last health check error if any
func (p *provider) GetLastHealthCheckError() error {
	return p.lastHealthCheck
}

// validateAWSConfig validates AWS KMS configuration
func validateAWSConfig(config Config) error {
	if config.KeyID == "" {
		return fmt.Errorf("key ID is required")
	}

	if config.Region == "" {
		return fmt.Errorf("region is required")
	}

	if config.Credentials != nil {
		_, hasAccessKey := config.Credentials["accessKeyId"].(string)
		_, hasSecretKey := config.Credentials["secretAccessKey"].(string)
		if (hasAccessKey && !hasSecretKey) || (!hasAccessKey && hasSecretKey) {
			return fmt.Errorf("both accessKeyId and secretAccessKey must be provided if using credentials")
		}
	}

	return nil
}

// validateAzureConfig validates Azure Key Vault configuration
func validateAzureConfig(config Config) error {
	if config.KeyID == "" {
		return fmt.Errorf("key ID is required")
	}

	if config.Credentials != nil {
		requiredFields := []string{"tenantId", "clientId", "clientSecret"}
		for _, field := range requiredFields {
			if _, ok := config.Credentials[field].(string); !ok {
				return fmt.Errorf("%s is required in credentials", field)
			}
		}
	}

	return nil
}

// validateGCPConfig validates GCP KMS configuration
func validateGCPConfig(config Config) error {
	if config.KeyID == "" {
		return fmt.Errorf("key ID is required")
	}

	if config.Region == "" {
		return fmt.Errorf("region is required")
	}

	if config.Credentials != nil {
		if _, ok := config.Credentials["credentialsJson"].(string); !ok {
			return fmt.Errorf("credentialsJson is required in credentials")
		}
	}

	return nil
}

// validateVaultConfig validates HashiCorp Vault configuration
func validateVaultConfig(config Config) error {
	if config.KeyID == "" {
		return fmt.Errorf("key ID is required")
	}

	if config.VaultAddress == "" {
		return fmt.Errorf("vault address is required")
	}

	if config.Credentials != nil {
		if _, ok := config.Credentials["token"].(string); !ok {
			return fmt.Errorf("token is required in credentials")
		}
	}

	return nil
}

// createAWSWrapper creates an AWS KMS wrapper
func createAWSWrapper(config Config) (wrapping.Wrapper, error) {
	wrapper := awskms.NewWrapper()

	// Create config map with AWS KMS specific options
	configMap := map[string]string{
		"kms_key_id": config.KeyID,
		"region":     config.Region,
	}

	// Add credentials if provided
	if config.Credentials != nil {
		// Log credential presence without exposing sensitive data
		hasCredentials := map[string]bool{
			"accessKey":    config.Credentials["accessKeyId"] != nil,
			"secretKey":    config.Credentials["secretAccessKey"] != nil,
			"sessionToken": config.Credentials["sessionToken"] != nil,
		}

		log.Debug().
			Interface("credentials", hasCredentials).
			Msg("Configuring AWS KMS credentials")

		if accessKey, ok := config.Credentials["accessKeyId"].(string); ok && accessKey != "" {
			configMap["access_key"] = accessKey
		}
		if secretKey, ok := config.Credentials["secretAccessKey"].(string); ok && secretKey != "" {
			configMap["secret_key"] = secretKey
		}
		if sessionToken, ok := config.Credentials["sessionToken"].(string); ok && sessionToken != "" {
			configMap["session_token"] = sessionToken
		}
	}

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure AWS KMS wrapper: %w", err)
	}

	return wrapper, nil
}

// createAzureWrapper creates an Azure Key Vault wrapper
func createAzureWrapper(config Config) (wrapping.Wrapper, error) {
	wrapper := azurekeyvault.NewWrapper()

	// Create config map with Azure Key Vault specific options
	configMap := map[string]string{
		"key_name": config.KeyID,
	}

	// Extract vault name from address if provided
	if config.VaultAddress != "" {
		vaultName := strings.Split(config.VaultAddress, ".")[0]
		configMap["vault_name"] = vaultName
	}

	// Add credentials if provided
	if config.Credentials != nil {
		// Log credential presence without exposing sensitive data
		hasCredentials := map[string]bool{
			"tenantId":     config.Credentials["tenantId"] != nil,
			"clientId":     config.Credentials["clientId"] != nil,
			"clientSecret": config.Credentials["clientSecret"] != nil,
		}

		log.Debug().
			Interface("credentials", hasCredentials).
			Msg("Configuring Azure Key Vault credentials")

		if tenantID, ok := config.Credentials["tenantId"].(string); ok {
			configMap["tenant_id"] = tenantID
		}
		if clientID, ok := config.Credentials["clientId"].(string); ok {
			configMap["client_id"] = clientID
		}
		if clientSecret, ok := config.Credentials["clientSecret"].(string); ok {
			configMap["client_secret"] = clientSecret
		}
	}

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Azure Key Vault wrapper: %w", err)
	}

	return wrapper, nil
}

// createGCPWrapper creates a Google Cloud KMS wrapper
func createGCPWrapper(config Config) (wrapping.Wrapper, error) {
	wrapper := gcpckms.NewWrapper()
	// Parse key ID to extract project, location, key ring, and crypto key
	//parts := strings.Split(config.KeyID, "/")
	//if len(parts) < 8 {
	//	return nil, fmt.Errorf("invalid GCP key ID format. Expected: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}")
	// Extract project ID from credentials JSON
	var projectID string
	if config.Credentials != nil {
		if credsJSON, ok := config.Credentials["credentialsJson"].(string); ok {
			// Parse project ID from credentials JSON
			// Note: This is a simplified example. In production, you should properly parse the JSON
			if strings.Contains(credsJSON, "project_id") {
				projectID = strings.Split(strings.Split(credsJSON, "project_id\":\"")[1], "\"")[0]
			}
		}
	}
	if projectID == "" {
		return nil, fmt.Errorf("project ID not found in credentials JSON")
	}

	// Construct the full key ID
	fullKeyID := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectID,
		config.Region,
		config.KeyRing,
		config.KeyID)

	// Create config map with GCP KMS specific options
	configMap := map[string]string{
		//"project":    parts[1],
		//"region":     parts[3],
		//"key_ring":   parts[5],
		//"crypto_key": parts[7],
		"key_id": fullKeyID,
	}

	// Add credentials if provided
	if config.Credentials != nil {
		// Log credential presence without exposing sensitive data
		hasCredentials := map[string]bool{
			"credentialsJson": config.Credentials["credentialsJson"] != nil,
		}

		log.Debug().
			Interface("credentials", hasCredentials).
			Msg("Configuring GCP KMS credentials")

		if credsJSON, ok := config.Credentials["credentialsJson"].(string); ok {
			configMap["credentials"] = credsJSON
		}
	}

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure GCP KMS wrapper: %w", err)
	}

	return wrapper, nil
}

// createVaultWrapper creates a HashiCorp Vault Transit wrapper
func createVaultWrapper(config Config) (wrapping.Wrapper, error) {
	wrapper := transit.NewWrapper()

	// Create config map with Vault Transit specific options
	configMap := map[string]string{
		"address":    config.VaultAddress,
		"mount_path": config.VaultMount,
		"key_name":   config.KeyID,
	}

	// Add credentials if provided
	if config.Credentials != nil {
		// Log credential presence without exposing sensitive data
		hasCredentials := map[string]bool{
			"token": config.Credentials["token"] != nil,
		}

		log.Debug().
			Interface("credentials", hasCredentials).
			Msg("Configuring Vault Transit credentials")

		if token, ok := config.Credentials["token"].(string); ok {
			configMap["token"] = token
		}
	}

	// Configure the wrapper
	_, err := wrapper.SetConfig(context.Background(), wrapping.WithConfigMap(configMap))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault Transit wrapper: %w", err)
	}

	return wrapper, nil
}
