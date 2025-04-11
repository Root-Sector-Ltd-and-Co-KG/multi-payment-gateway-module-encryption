package types

import (
	"sync"
	"time"
)

// Type represents the type of encryption task
type Type string

const (
	TypeFieldEncrypt  Type = "field_encrypt"
	TypeFieldDecrypt  Type = "field_decrypt"
	TypeFieldVerify   Type = "field_verify"
	TypeDEKRotation   Type = "dek_rotation"
	TypeFieldRollback Type = "field_rollback"
)

// Status represents the current state of a task or processor
type Status string

const (
	// StatusPending indicates the task is waiting to be processed
	StatusPending Status = "pending"

	// StatusProcessing indicates the task is currently being processed
	StatusProcessing Status = "processing"

	// StatusCompleted indicates the task has finished successfully
	StatusCompleted Status = "completed"

	// StatusCompletedWithErrors indicates the task finished, but some operations failed
	StatusCompletedWithErrors Status = "completed_with_errors"

	// StatusFailed indicates the task has failed
	StatusFailed Status = "failed"

	// StatusCancelled indicates the task was cancelled by user or system
	StatusCancelled Status = "cancelled"

	// StatusPaused indicates the task execution is temporarily paused
	StatusPaused Status = "paused"
)

// Scope represents the scope of an encryption task
type Scope string

const (
	ScopeSystem       Scope = "system"
	ScopeOrganization Scope = "organization"
)

// Config holds configuration for the batch field processor
type Config struct {
	// Workers is the number of concurrent workers
	Workers int `json:"workers" bson:"workers"`

	// BatchSize is the number of items to process in each batch
	BatchSize int `json:"batchSize" bson:"batchSize"`

	// MaxRetries is the maximum number of retries for failed operations
	MaxRetries int `json:"maxRetries" bson:"maxRetries"`

	// AuditLogger enables audit logging
	AuditLogger bool `json:"auditLogger" bson:"auditLogger"`
}

// Stats holds statistics about the batch field processor
type DBEncryptionStats struct {
	FailedTasks     uint64    `json:"failedTasks" bson:"failedTasks"`
	LastTaskTime    time.Time `json:"lastTaskTime" bson:"lastTaskTime"`
	LastSuccessTime time.Time `json:"lastSuccessTime" bson:"lastSuccessTime"`
	LastFailureTime time.Time `json:"lastFailureTime" bson:"lastFailureTime"`
	TotalProcessed  int64     `json:"totalProcessed" bson:"totalProcessed"`
	TotalFailed     int64     `json:"totalFailed" bson:"totalFailed"`
}

// Progress tracks the progress of field processing
type Progress struct {
	Total     int64   `json:"total" bson:"total"`
	Processed int64   `json:"processed" bson:"processed"`
	Failed    int64   `json:"failed" bson:"failed"`
	Percent   float64 `json:"percent" bson:"percent"`
}

// Logger defines a minimal logging interface
type Logger interface {
	Printf(format string, v ...interface{})
}

// BatchFieldProcessor handles batch encryption/decryption of database fields
type BatchFieldProcessor struct {
	ID           string            `json:"id" bson:"_id"`
	Status       Status            `json:"status" bson:"status"`
	Progress     Progress          `json:"progress" bson:"progress"`
	Config       Config            `json:"config" bson:"config"`
	Stats        DBEncryptionStats `json:"stats" bson:"stats"`
	CreatedAt    time.Time         `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt" bson:"updatedAt"`
	dekService   interface{}       // Use interface{} to avoid circular dependency
	fieldService interface{}       // Use interface{} to avoid circular dependency
	auditLogger  Logger
	logger       Logger
	//taskStore    TaskStore
	workerPool  *sync.WaitGroup
	taskQueue   chan *Task
	resultQueue chan *TaskResult
	stopChan    chan struct{}
}

// Task represents an encryption task
type Task struct {
	ID         string                 `json:"id" bson:"_id"`
	Type       Type                   `json:"type" bson:"type"`
	Scope      Scope                  `json:"scope" bson:"scope"`
	Collection string                 `json:"collection" bson:"collection"`
	Status     Status                 `json:"status" bson:"status"`
	Error      string                 `json:"error,omitempty" bson:"error,omitempty"`
	Progress   float64                `json:"progress" bson:"progress"`
	BatchSize  int                    `json:"batchSize" bson:"batchSize"`
	MaxRetries int                    `json:"maxRetries" bson:"maxRetries"`
	Priority   int                    `json:"priority" bson:"priority"`
	Metadata   map[string]interface{} `json:"metadata" bson:"metadata"`
	CreatedAt  time.Time              `json:"createdAt" bson:"createdAt"`
	UpdatedAt  time.Time              `json:"updatedAt" bson:"updatedAt"`
}

// TaskResult represents the result of a task
type TaskResult struct {
	TaskID         string `json:"taskId" bson:"taskId"`
	Status         Status `json:"status" bson:"status"`
	Error          string `json:"error,omitempty" bson:"error,omitempty"`
	Processed      int64  `json:"processed" bson:"processed"`
	Failed         int64  `json:"failed" bson:"failed"`
	ProcessedCount int64  `json:"processed_count" bson:"processed_count"`
	Collection     string `json:"collection,omitempty" bson:"collection,omitempty"`
}
