package credentials

import (
	"reflect"
	"testing"

	"github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/kms"
	encTypes "github.com/root-sector-ltd-and-co-kg/payment-gateway-lib-crypto/types"
)

func TestToKMSConfig(t *testing.T) {
	// Sample input EncryptionConfig data
	awsInput := &encTypes.EncryptionConfig{
		Provider: encTypes.ProviderAWS,
		KeyID:    "aws-arn",
		Region:   "us-west-2",
		Credentials: &encTypes.KMSCredentials{
			AccessKeyID:     "AKIA...",
			SecretAccessKey: "SECRET...",
		},
	}
	azureInput := &encTypes.EncryptionConfig{
		Provider:     encTypes.ProviderAzure,
		KeyID:        "https://a.vault.azure.net/k/b/c",
		VaultAddress: "https://a.vault.azure.net",
		Credentials: &encTypes.KMSCredentials{
			TenantID:     "TENANT",
			ClientID:     "CLIENT",
			ClientSecret: "SECRET",
		},
	}
	gcpInput := &encTypes.EncryptionConfig{
		Provider: encTypes.ProviderGCP,
		KeyID:    "projects/p/locations/l/keyRings/r/cryptoKeys/k", // ResourceName stored in KeyID
		// Region and KeyRing are deprecated/removed from EncryptionConfig
		Credentials: &encTypes.KMSCredentials{
			CredentialsJSON: `{"project_id":"p"}`,
		},
	}
	vaultInput := &encTypes.EncryptionConfig{
		Provider:     encTypes.ProviderVault,
		KeyID:        "vault-key-name",
		VaultAddress: "https://v.example.com",
		VaultMount:   "transit",
		Credentials: &encTypes.KMSCredentials{
			Token: "VAULT_TOKEN",
		},
	}

	// Expected output kms.Config data
	expectedAWS := kms.Config{
		Type: encTypes.ProviderAWS,
		AWS: &kms.AWSConfig{
			KeyID:  "aws-arn",
			Region: "us-west-2",
			Credentials: map[string]interface{}{
				"accessKeyId":     "AKIA...",
				"secretAccessKey": "SECRET...",
			},
		},
	}
	expectedAzure := kms.Config{
		Type: encTypes.ProviderAzure,
		Azure: &kms.AzureConfig{
			KeyID:        "https://a.vault.azure.net/k/b/c",
			VaultAddress: "https://a.vault.azure.net",
			Credentials: map[string]interface{}{
				"tenantId":     "TENANT",
				"clientId":     "CLIENT",
				"clientSecret": "SECRET",
			},
		},
	}
	expectedGCP := kms.Config{
		Type: encTypes.ProviderGCP,
		GCP: &kms.GCPConfig{
			ResourceName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			Credentials: map[string]interface{}{
				"credentialsJson": `{"project_id":"p"}`,
			},
		},
	}
	expectedVault := kms.Config{
		Type: encTypes.ProviderVault,
		Vault: &kms.VaultConfig{
			KeyID:        "vault-key-name",
			VaultAddress: "https://v.example.com",
			VaultMount:   "transit",
			Credentials: map[string]interface{}{
				"token": "VAULT_TOKEN",
			},
		},
	}

	tests := []struct {
		name     string
		input    *encTypes.EncryptionConfig
		expected kms.Config
	}{
		{
			name:     "AWS Conversion",
			input:    awsInput,
			expected: expectedAWS,
		},
		{
			name:     "Azure Conversion",
			input:    azureInput,
			expected: expectedAzure,
		},
		{
			name:     "GCP Conversion",
			input:    gcpInput,
			expected: expectedGCP,
		},
		{
			name:     "Vault Conversion",
			input:    vaultInput,
			expected: expectedVault,
		},
		{
			name:     "Nil Input",
			input:    nil,
			expected: kms.Config{}, // Expect empty config
		},
		{
			name: "Unsupported Provider",
			input: &encTypes.EncryptionConfig{
				Provider: "unknown",
				KeyID:    "some-key",
			},
			expected: kms.Config{Type: "unknown"}, // Only type should be set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toKMSConfig(tt.input)
			// Use reflect.DeepEqual for comparing nested structs and maps
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("toKMSConfig() = %+v, want %+v", result, tt.expected)
				// Log specific differences for easier debugging
				if result.Type != tt.expected.Type {
					t.Errorf("Type mismatch: got %v, want %v", result.Type, tt.expected.Type)
				}
				if !reflect.DeepEqual(result.AWS, tt.expected.AWS) {
					t.Errorf("AWS config mismatch: got %+v, want %+v", result.AWS, tt.expected.AWS)
				}
				if !reflect.DeepEqual(result.Azure, tt.expected.Azure) {
					t.Errorf("Azure config mismatch: got %+v, want %+v", result.Azure, tt.expected.Azure)
				}
				if !reflect.DeepEqual(result.GCP, tt.expected.GCP) {
					t.Errorf("GCP config mismatch: got %+v, want %+v", result.GCP, tt.expected.GCP)
				}
				if !reflect.DeepEqual(result.Vault, tt.expected.Vault) {
					t.Errorf("Vault config mismatch: got %+v, want %+v", result.Vault, tt.expected.Vault)
				}
			}
		})
	}
}

// --- TODO: Add Tests for EncryptCredentials and DecryptCredentials ---
// These would require mocking the encryptor interface.
