package dns

import (
	"sync"
	"time"
)

// Cache provides a simple TTL-aware DNS result cache.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

var globalCache *Cache

// InitCache creates the global DNS cache with the given TTL.
func InitCache(ttlSeconds int) {
	globalCache = &Cache{
		entries: make(map[string]*cacheEntry),
		ttl:     time.Duration(ttlSeconds) * time.Second,
	}
	// Start background cleanup
	go globalCache.cleanup()
}

// Get retrieves a value from the cache. Returns (nil, false) if not found or expired.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// Set stores a value in the cache with the configured TTL.
func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// SetWithTTL stores a value in the cache with a custom TTL.
func (c *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

// cleanup periodically removes expired entries.
func (c *Cache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}
