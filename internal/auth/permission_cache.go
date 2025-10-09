package auth

import (
	"sync"
	"time"
)

// PermissionCacheImpl implements permission caching for performance
type PermissionCacheImpl struct {
	cache   map[string]*PermissionCache
	mutex   sync.RWMutex
	stats   CacheStats
	maxSize int
}

// CacheStats represents cache statistics
type CacheStats struct {
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	Evictions int64   `json:"evictions"`
	Size      int     `json:"size"`
	MaxSize   int     `json:"max_size"`
	HitRate   float64 `json:"hit_rate"`
}

// NewPermissionCache creates a new permission cache
func NewPermissionCache() *PermissionCacheImpl {
	cache := &PermissionCacheImpl{
		cache:   make(map[string]*PermissionCache),
		maxSize: 10000, // Maximum cache entries
	}

	// Start cleanup routine
	go cache.cleanupRoutine()

	return cache
}

// Get retrieves a cached permission result
func (pc *PermissionCacheImpl) Get(userID, resource, action, contextHash string) *PermissionCache {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	key := pc.buildKey(userID, resource, action, contextHash)
	entry, exists := pc.cache[key]

	if !exists {
		pc.stats.Misses++
		return nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		pc.stats.Misses++
		// Don't delete here to avoid write lock, cleanup routine will handle it
		return nil
	}

	pc.stats.Hits++
	return entry
}

// Set stores a permission result in the cache
func (pc *PermissionCacheImpl) Set(userID, resource, action, contextHash string, result bool, ttl time.Duration) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	// Check if we need to evict entries
	if len(pc.cache) >= pc.maxSize {
		pc.evictOldest()
	}

	key := pc.buildKey(userID, resource, action, contextHash)
	entry := &PermissionCache{
		UserID:    userID,
		Resource:  resource,
		Action:    action,
		Result:    result,
		ExpiresAt: time.Now().Add(ttl),
		Context:   contextHash,
	}

	pc.cache[key] = entry
}

// InvalidateUser removes all cached permissions for a user
func (pc *PermissionCacheImpl) InvalidateUser(userID string) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	keysToDelete := make([]string, 0)

	for key, entry := range pc.cache {
		if entry.UserID == userID {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(pc.cache, key)
		pc.stats.Evictions++
	}
}

// InvalidateResource removes all cached permissions for a resource
func (pc *PermissionCacheImpl) InvalidateResource(resource string) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	keysToDelete := make([]string, 0)

	for key, entry := range pc.cache {
		if entry.Resource == resource {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(pc.cache, key)
		pc.stats.Evictions++
	}
}

// Clear removes all cached permissions
func (pc *PermissionCacheImpl) Clear() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	evicted := len(pc.cache)
	pc.cache = make(map[string]*PermissionCache)
	pc.stats.Evictions += int64(evicted)
}

// GetStats returns cache statistics
func (pc *PermissionCacheImpl) GetStats() map[string]interface{} {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	total := pc.stats.Hits + pc.stats.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(pc.stats.Hits) / float64(total)
	}

	return map[string]interface{}{
		"hits":      pc.stats.Hits,
		"misses":    pc.stats.Misses,
		"evictions": pc.stats.Evictions,
		"size":      len(pc.cache),
		"max_size":  pc.maxSize,
		"hit_rate":  hitRate,
	}
}

// buildKey creates a cache key from permission parameters
func (pc *PermissionCacheImpl) buildKey(userID, resource, action, contextHash string) string {
	return userID + ":" + resource + ":" + action + ":" + contextHash
}

// evictOldest removes the oldest cache entries to make room for new ones
func (pc *PermissionCacheImpl) evictOldest() {
	if len(pc.cache) == 0 {
		return
	}

	// Find the oldest entry
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range pc.cache {
		if first || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
			first = false
		}
	}

	if oldestKey != "" {
		delete(pc.cache, oldestKey)
		pc.stats.Evictions++
	}
}

// cleanupRoutine periodically removes expired cache entries
func (pc *PermissionCacheImpl) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		pc.cleanup()
	}
}

// cleanup removes expired cache entries
func (pc *PermissionCacheImpl) cleanup() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	now := time.Now()
	keysToDelete := make([]string, 0)

	for key, entry := range pc.cache {
		if now.After(entry.ExpiresAt) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(pc.cache, key)
		pc.stats.Evictions++
	}
}

// SetMaxSize sets the maximum cache size
func (pc *PermissionCacheImpl) SetMaxSize(maxSize int) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	pc.maxSize = maxSize

	// Evict entries if current size exceeds new max size
	for len(pc.cache) > pc.maxSize {
		pc.evictOldest()
	}
}

// GetSize returns the current cache size
func (pc *PermissionCacheImpl) GetSize() int {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	return len(pc.cache)
}

// GetMaxSize returns the maximum cache size
func (pc *PermissionCacheImpl) GetMaxSize() int {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()

	return pc.maxSize
}

// ResetStats resets cache statistics
func (pc *PermissionCacheImpl) ResetStats() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	pc.stats = CacheStats{
		MaxSize: pc.maxSize,
	}
}
