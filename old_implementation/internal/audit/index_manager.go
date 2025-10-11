package audit

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// IndexConfig defines configuration for database indexes
type IndexConfig struct {
	Name      string    `json:"name"`
	Table     string    `json:"table"`
	Columns   []string  `json:"columns"`
	Unique    bool      `json:"unique"`
	Partial   string    `json:"partial,omitempty"`
	Type      string    `json:"type"` // btree, hash, gin, gist
	CreatedAt time.Time `json:"created_at"`
}

// IndexManager handles database indexing for audit logs
type IndexManager struct {
	db      *sql.DB
	indexes map[string]IndexConfig
	mutex   sync.RWMutex
}

// QueryPerformanceStats represents query performance statistics
type QueryPerformanceStats struct {
	AverageQueryTime        time.Duration            `json:"average_query_time"`
	SlowestQueries          []SlowQuery              `json:"slowest_queries"`
	IndexUsageStats         map[string]IndexUsage    `json:"index_usage_stats"`
	QueryPatterns           []QueryPattern           `json:"query_patterns"`
	OptimizationSuggestions []OptimizationSuggestion `json:"optimization_suggestions"`
	LastAnalyzed            time.Time                `json:"last_analyzed"`
}

// SlowQuery represents a slow query
type SlowQuery struct {
	Query         string        `json:"query"`
	ExecutionTime time.Duration `json:"execution_time"`
	Frequency     int           `json:"frequency"`
	LastSeen      time.Time     `json:"last_seen"`
}

// IndexUsage represents index usage statistics
type IndexUsage struct {
	IndexName  string    `json:"index_name"`
	UsageCount int64     `json:"usage_count"`
	LastUsed   time.Time `json:"last_used"`
	Efficiency float64   `json:"efficiency"`
	SizeBytes  int64     `json:"size_bytes"`
}

// QueryPattern represents common query patterns
type QueryPattern struct {
	Pattern    string        `json:"pattern"`
	Frequency  int           `json:"frequency"`
	AvgTime    time.Duration `json:"avg_time"`
	Complexity string        `json:"complexity"`
}

// OptimizationSuggestion represents an optimization suggestion
type OptimizationSuggestion struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Query       string `json:"query,omitempty"`
	IndexName   string `json:"index_name,omitempty"`
}

// ArchiveInfo represents archive information
type ArchiveInfo struct {
	TotalArchives     int       `json:"total_archives"`
	TotalArchivedSize int64     `json:"total_archived_size"`
	OldestArchive     time.Time `json:"oldest_archive"`
	NewestArchive     time.Time `json:"newest_archive"`
	ArchiveLocations  []string  `json:"archive_locations"`
	CompressionRatio  float64   `json:"compression_ratio"`
}

// NewIndexManager creates a new index manager
func NewIndexManager(db *sql.DB) *IndexManager {
	return &IndexManager{
		db:      db,
		indexes: make(map[string]IndexConfig),
	}
}

// CreateIndex creates a database index
func (im *IndexManager) CreateIndex(config IndexConfig) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	// Check if index already exists
	if _, exists := im.indexes[config.Name]; exists {
		return fmt.Errorf("index %s already exists", config.Name)
	}

	// Build CREATE INDEX statement
	query := im.buildCreateIndexQuery(config)

	// Execute the query
	_, err := im.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create index %s: %w", config.Name, err)
	}

	// Store index configuration
	config.CreatedAt = time.Now()
	im.indexes[config.Name] = config

	return nil
}

// DropIndex drops a database index
func (im *IndexManager) DropIndex(indexName string) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	// Check if index exists
	if _, exists := im.indexes[indexName]; !exists {
		return fmt.Errorf("index %s does not exist", indexName)
	}

	// Drop the index
	query := fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)
	_, err := im.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to drop index %s: %w", indexName, err)
	}

	// Remove from configuration
	delete(im.indexes, indexName)

	return nil
}

// GetIndexes returns all configured indexes
func (im *IndexManager) GetIndexes() map[string]IndexConfig {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]IndexConfig)
	for name, config := range im.indexes {
		result[name] = config
	}

	return result
}

// OptimizeIndexes analyzes and optimizes database indexes
func (im *IndexManager) OptimizeIndexes() error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	// Analyze index usage
	usage, err := im.analyzeIndexUsage()
	if err != nil {
		return fmt.Errorf("failed to analyze index usage: %w", err)
	}

	// Identify unused indexes
	unusedIndexes := im.identifyUnusedIndexes(usage)

	// Drop unused indexes (with caution)
	for _, indexName := range unusedIndexes {
		if im.isSafeToDropIndex(indexName) {
			if err := im.DropIndex(indexName); err != nil {
				fmt.Printf("Warning: failed to drop unused index %s: %v\n", indexName, err)
			}
		}
	}

	// Suggest new indexes based on query patterns
	suggestions := im.suggestNewIndexes()
	for _, suggestion := range suggestions {
		fmt.Printf("Index suggestion: %s\n", suggestion.Description)
	}

	return nil
}

// GetQueryPerformance returns query performance statistics
func (im *IndexManager) GetQueryPerformance() (*QueryPerformanceStats, error) {
	stats := &QueryPerformanceStats{
		LastAnalyzed: time.Now(),
	}

	// Get index usage statistics
	usage, err := im.analyzeIndexUsage()
	if err != nil {
		return nil, fmt.Errorf("failed to analyze index usage: %w", err)
	}
	stats.IndexUsageStats = usage

	// Get slow queries (simplified for SQLite)
	slowQueries, err := im.getSlowQueries()
	if err != nil {
		return nil, fmt.Errorf("failed to get slow queries: %w", err)
	}
	stats.SlowestQueries = slowQueries

	// Calculate average query time (estimated)
	stats.AverageQueryTime = 10 * time.Millisecond // Placeholder

	// Generate optimization suggestions
	stats.OptimizationSuggestions = im.generateOptimizationSuggestions(usage, slowQueries)

	return stats, nil
}

// Helper methods

func (im *IndexManager) buildCreateIndexQuery(config IndexConfig) string {
	var query strings.Builder

	// Start with CREATE INDEX
	if config.Unique {
		query.WriteString("CREATE UNIQUE INDEX IF NOT EXISTS ")
	} else {
		query.WriteString("CREATE INDEX IF NOT EXISTS ")
	}

	query.WriteString(config.Name)
	query.WriteString(" ON ")
	query.WriteString(config.Table)

	// Add index type if specified (for PostgreSQL compatibility)
	if config.Type != "" && config.Type != "btree" {
		query.WriteString(" USING ")
		query.WriteString(config.Type)
	}

	// Add columns
	query.WriteString(" (")
	query.WriteString(strings.Join(config.Columns, ", "))
	query.WriteString(")")

	// Add partial index condition if specified
	if config.Partial != "" {
		query.WriteString(" WHERE ")
		query.WriteString(config.Partial)
	}

	return query.String()
}

func (im *IndexManager) analyzeIndexUsage() (map[string]IndexUsage, error) {
	usage := make(map[string]IndexUsage)

	// For SQLite, we can query sqlite_master for index information
	query := `
		SELECT name, sql 
		FROM sqlite_master 
		WHERE type = 'index' 
		AND name LIKE 'idx_audit_%'`

	rows, err := im.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var indexName, sql string
		if err := rows.Scan(&indexName, &sql); err != nil {
			continue
		}

		// Create usage statistics (simplified)
		usage[indexName] = IndexUsage{
			IndexName:  indexName,
			UsageCount: 100, // Placeholder - would need query plan analysis
			LastUsed:   time.Now().Add(-time.Hour),
			Efficiency: 85.0, // Placeholder
			SizeBytes:  1024, // Placeholder
		}
	}

	return usage, nil
}

func (im *IndexManager) identifyUnusedIndexes(usage map[string]IndexUsage) []string {
	var unused []string

	for indexName, stats := range usage {
		// Consider index unused if not used in the last 30 days
		if time.Since(stats.LastUsed) > 30*24*time.Hour && stats.UsageCount < 10 {
			unused = append(unused, indexName)
		}
	}

	return unused
}

func (im *IndexManager) isSafeToDropIndex(indexName string) bool {
	// Don't drop essential indexes
	essentialIndexes := []string{
		"idx_audit_timestamp",
		"idx_audit_user_id",
		"idx_audit_event_type",
	}

	for _, essential := range essentialIndexes {
		if indexName == essential {
			return false
		}
	}

	return true
}

func (im *IndexManager) suggestNewIndexes() []OptimizationSuggestion {
	suggestions := make([]OptimizationSuggestion, 0)

	// Analyze common query patterns and suggest indexes
	// This is a simplified implementation

	// Suggest composite indexes for common filter combinations
	suggestions = append(suggestions, OptimizationSuggestion{
		Type:        "COMPOSITE_INDEX",
		Description: "Create composite index on (user_id, timestamp) for user activity queries",
		Impact:      "HIGH",
		Query:       "CREATE INDEX idx_audit_user_timestamp ON audit_entries (user_id, timestamp)",
	})

	suggestions = append(suggestions, OptimizationSuggestion{
		Type:        "PARTIAL_INDEX",
		Description: "Create partial index on error entries for faster error analysis",
		Impact:      "MEDIUM",
		Query:       "CREATE INDEX idx_audit_errors ON audit_entries (timestamp) WHERE success = false",
	})

	return suggestions
}

func (im *IndexManager) getSlowQueries() ([]SlowQuery, error) {
	// For SQLite, we can't easily get actual slow query logs
	// This is a placeholder implementation
	slowQueries := []SlowQuery{
		{
			Query:         "SELECT * FROM audit_entries WHERE search_text LIKE '%pattern%'",
			ExecutionTime: 500 * time.Millisecond,
			Frequency:     25,
			LastSeen:      time.Now().Add(-time.Hour),
		},
		{
			Query:         "SELECT COUNT(*) FROM audit_entries GROUP BY user_id",
			ExecutionTime: 200 * time.Millisecond,
			Frequency:     15,
			LastSeen:      time.Now().Add(-2 * time.Hour),
		},
	}

	return slowQueries, nil
}

func (im *IndexManager) generateOptimizationSuggestions(usage map[string]IndexUsage, slowQueries []SlowQuery) []OptimizationSuggestion {
	suggestions := make([]OptimizationSuggestion, 0)

	// Analyze slow queries and suggest optimizations
	for _, query := range slowQueries {
		if strings.Contains(query.Query, "LIKE") && strings.Contains(query.Query, "search_text") {
			suggestions = append(suggestions, OptimizationSuggestion{
				Type:        "INDEX_OPTIMIZATION",
				Description: "Consider using full-text search index for text searches",
				Impact:      "HIGH",
				Query:       query.Query,
			})
		}

		if strings.Contains(query.Query, "GROUP BY") && query.ExecutionTime > 100*time.Millisecond {
			suggestions = append(suggestions, OptimizationSuggestion{
				Type:        "QUERY_OPTIMIZATION",
				Description: "Consider adding covering index for GROUP BY operations",
				Impact:      "MEDIUM",
				Query:       query.Query,
			})
		}
	}

	// Analyze index usage and suggest improvements
	for indexName, stats := range usage {
		if stats.Efficiency < 50.0 {
			suggestions = append(suggestions, OptimizationSuggestion{
				Type:        "INDEX_MAINTENANCE",
				Description: fmt.Sprintf("Index %s has low efficiency (%.1f%%), consider rebuilding", indexName, stats.Efficiency),
				Impact:      "MEDIUM",
				IndexName:   indexName,
			})
		}
	}

	return suggestions
}

// CompressionManager handles log compression
type CompressionManager struct {
	enabled   bool
	algorithm string
	threshold int64
	mutex     sync.RWMutex
}

// NewCompressionManager creates a new compression manager
func NewCompressionManager(enabled bool) *CompressionManager {
	return &CompressionManager{
		enabled:   enabled,
		algorithm: "gzip",
		threshold: 1024 * 1024, // 1MB
	}
}

// CompressData compresses data if compression is enabled
func (cm *CompressionManager) CompressData(data []byte) ([]byte, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if !cm.enabled || int64(len(data)) < cm.threshold {
		return data, nil
	}

	// Placeholder for actual compression implementation
	// In a real implementation, this would use gzip, zstd, or another algorithm
	return data, nil
}

// DecompressData decompresses data if it was compressed
func (cm *CompressionManager) DecompressData(data []byte) ([]byte, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	if !cm.enabled {
		return data, nil
	}

	// Placeholder for actual decompression implementation
	return data, nil
}

// IsCompressionEnabled returns whether compression is enabled
func (cm *CompressionManager) IsCompressionEnabled() bool {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return cm.enabled
}

// SetCompressionEnabled enables or disables compression
func (cm *CompressionManager) SetCompressionEnabled(enabled bool) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	cm.enabled = enabled
}

// GetCompressionStats returns compression statistics
func (cm *CompressionManager) GetCompressionStats() map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return map[string]interface{}{
		"enabled":   cm.enabled,
		"algorithm": cm.algorithm,
		"threshold": cm.threshold,
	}
}
