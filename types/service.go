package types

// Stats represents service statistics
type Stats struct {
	CacheStats interface{} `json:"cacheStats,omitempty"`
	FieldStats interface{} `json:"fieldStats,omitempty"`
}
