package types

import (
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Info contains information about a Data Encryption Key
type DEKInfo struct {
	Id        string       `json:"id" bson:"_id"`
	Version   int          `json:"version" bson:"version"`
	Active    bool         `json:"active" bson:"active"`
	Versions  []DEKVersion `json:"versions" bson:"versions"`
	CreatedAt time.Time    `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt" bson:"updatedAt"`
}

// DEKVersion represents a specific version of a DEK
type DEKVersion struct {
	// Version number
	Version int `bson:"version" json:"version"`

	// Store complete BlobInfo from KMS wrapper
	BlobInfo *wrapping.BlobInfo `bson:"blobInfo" json:"blobInfo"`

	// Creation timestamp
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`

	// WrapContext is used only during wrapping verification
	// It is not persisted to storage
	WrapContext []byte `bson:"wrapContext,omitempty" json:"-"`
}

// For backward compatibility, we'll add methods to access individual fields
func (v *DEKVersion) GetIV() []byte {
	if v.BlobInfo == nil {
		return nil
	}
	return v.BlobInfo.Iv
}

func (v *DEKVersion) GetHmac() []byte {
	if v.BlobInfo == nil {
		return nil
	}
	return v.BlobInfo.Hmac
}

func (v *DEKVersion) GetCiphertext() []byte {
	if v.BlobInfo == nil {
		return nil
	}
	return v.BlobInfo.Ciphertext
}

func (v *DEKVersion) GetKeyID() string {
	if v.BlobInfo == nil || v.BlobInfo.KeyInfo == nil {
		return ""
	}
	return v.BlobInfo.KeyInfo.KeyId
}

func (v *DEKVersion) GetWrappedKey() []byte {
	if v.BlobInfo == nil || v.BlobInfo.KeyInfo == nil {
		return nil
	}
	return v.BlobInfo.KeyInfo.WrappedKey
}

func (v *DEKVersion) GetMechanism() uint64 {
	if v.BlobInfo == nil || v.BlobInfo.KeyInfo == nil {
		return 0
	}
	return v.BlobInfo.KeyInfo.Mechanism
}

func (v *DEKVersion) GetHmacMechanism() uint64 {
	if v.BlobInfo == nil || v.BlobInfo.KeyInfo == nil {
		return 0
	}
	return v.BlobInfo.KeyInfo.HmacMechanism
}

func (v *DEKVersion) GetHmacKeyID() string {
	if v.BlobInfo == nil || v.BlobInfo.KeyInfo == nil {
		return ""
	}
	return v.BlobInfo.KeyInfo.HmacKeyId
}

func (v *DEKVersion) GetFlags() uint64 {
	if v.BlobInfo == nil || v.BlobInfo.KeyInfo == nil {
		return 0
	}
	return v.BlobInfo.KeyInfo.Flags
}

// Status represents the status of a DEK
type DEKStatus struct {
	Exists        bool         `json:"exists" bson:"exists"`
	Active        bool         `json:"active" bson:"active"`
	Version       int          `json:"version" bson:"version"`
	CreatedAt     time.Time    `json:"createdAt" bson:"createdAt"`
	UpdatedAt     time.Time    `json:"updatedAt" bson:"updatedAt"`
	Provider      ProviderType `json:"provider" bson:"provider"`
	ProviderKeyID string       `json:"providerKeyId,omitempty" bson:"providerKeyId,omitempty"`
	NeedsRotate   bool         `json:"needsRotate" bson:"needsRotate"`
}

// Stats holds statistics about the DEK service
type DEKStats struct {
	TotalDEKs     int       `json:"totalDEKs" bson:"totalDEKs"`
	ActiveDEKs    int       `json:"activeDEKs" bson:"activeDEKs"`
	InactiveDEKs  int       `json:"inactiveDEKs" bson:"inactiveDEKs"`
	RotatingDEKs  int       `json:"rotatingDEKs" bson:"rotatingDEKs"`
	LastRotation  time.Time `json:"lastRotation" bson:"lastRotation"`
	LastOperation time.Time `json:"lastOperation" bson:"lastOperation"`
}

// Config holds configuration for DEK management
type DEKConfig struct {
	// Workers is the number of concurrent workers for DEK operations
	Workers int `json:"workers" bson:"workers"`

	// BatchSize is the number of items to process in each batch
	BatchSize int `json:"batchSize" bson:"batchSize"`

	// MaxRetries is the maximum number of retries for failed operations
	MaxRetries int `json:"maxRetries" bson:"maxRetries"`

	// AuditLogger enables audit logging of DEK operations
	AuditLogger bool `json:"auditLogger" bson:"auditLogger"`

	// Cache holds the caching configuration
	Cache *CacheConfig `json:"cache" bson:"cache"`
}
