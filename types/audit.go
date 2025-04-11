package types

import (
	"time"
)

// AuditEvent represents an encryption-related audit event
type AuditEvent struct {
	ID         string                 `json:"id" bson:"_id"`
	Timestamp  time.Time              `json:"timestamp" bson:"timestamp"`
	EventType  string                 `json:"event_type" bson:"event_type"`
	Operation  string                 `json:"operation" bson:"operation"`
	Status     string                 `json:"status" bson:"status"`
	DEKVersion int                    `json:"dek_version" bson:"dek_version"`
	Context    map[string]string      `json:"context" bson:"context"`
	Metadata   map[string]interface{} `json:"metadata" bson:"metadata"`
}
