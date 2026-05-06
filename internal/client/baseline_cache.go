// Package client provides HTTP clients for cross-BC queries.
package client

import (
	"context"
	"sync"
	"time"

	"github.com/go-logr/logr"

	vplogging "vigilprotector.io/vp-lib/logging"
)

// BaselineCache provides caching for StratoSage baselines to reduce API calls
// and improve performance. It implements the BaselineProvider interface.
// SS-BP-004: Optimizes baseline consumption by caching frequently accessed baselines.
type BaselineCache struct {
	// provider is the underlying baseline provider (e.g., StratoSageClient)
	provider BaselineProvider

	// cache stores cached baselines by cache key
	cache map[string]*cacheEntry

	// mu protects the cache
	mu sync.RWMutex

	// ttl is the time-to-live for cache entries
	ttl time.Duration

	// logger for logging cache operations
	logger logr.Logger
}

// cacheEntry represents a cached baseline with its expiration time.
type cacheEntry struct {
	baseline   *Baseline
	expiresAt time.Time
}

// BaselineCacheConfig holds configuration for creating a BaselineCache.
type BaselineCacheConfig struct {
	// Provider is the underlying baseline provider
	Provider BaselineProvider
	// TTL is the time-to-live for cache entries (default: 5 minutes)
	TTL time.Duration
	// Logger for cache operations
	Logger logr.Logger
}

// DefaultBaselineCacheTTL is the default TTL for baseline cache entries.
const DefaultBaselineCacheTTL = 5 * time.Minute

// NewBaselineCache creates a new BaselineCache with the given configuration.
// If TTL is zero, it defaults to DefaultBaselineCacheTTL.
func NewBaselineCache(cfg BaselineCacheConfig) *BaselineCache {
	if cfg.TTL == 0 {
		cfg.TTL = DefaultBaselineCacheTTL
	}

	if cfg.Logger == (logr.Logger{}) {
		cfg.Logger = logr.Discard()
	}

	return &BaselineCache{
		provider: cfg.Provider,
		cache:    make(map[string]*cacheEntry),
		ttl:     cfg.TTL,
		logger:  cfg.Logger.WithName("baseline-cache"),
	}
}

// GetBaseline retrieves a baseline from the cache or the underlying provider.
// If the baseline is in the cache and not expired, it returns the cached value.
// Otherwise, it fetches from the provider and caches the result.
func (c *BaselineCache) GetBaseline(
	ctx context.Context,
	scopeRef string,
	featureSet string,
) (*Baseline, error) {
	// Build cache key
	cacheKey := buildCacheKey(scopeRef, featureSet)

	// Try to get from cache
	c.mu.RLock()
	entry, exists := c.cache[cacheKey]
	c.mu.RUnlock()

	if exists && !entry.expiresAt.Before(time.Now()) {
		// Cache hit - return cached baseline
		c.logger.V(vplogging.LogLevelDebug).Info("baseline cache hit",
			"scopeRef", scopeRef,
			"featureSet", featureSet)
		return entry.baseline, nil
	}

	// Cache miss - fetch from provider
	c.logger.V(vplogging.LogLevelDebug).Info("baseline cache miss",
		"scopeRef", scopeRef,
		"featureSet", featureSet)

	baseline, err := c.provider.GetBaseline(ctx, scopeRef, featureSet)
	if err != nil {
		return nil, err
	}

	// Cache the result if not nil
	if baseline != nil {
		c.mu.Lock()
		c.cache[cacheKey] = &cacheEntry{
			baseline:   baseline,
			expiresAt: time.Now().Add(c.ttl),
		}
		c.mu.Unlock()

		c.logger.V(vplogging.LogLevelVerbose).Info("cached baseline",
			"scopeRef", scopeRef,
			"featureSet", featureSet,
			"ttl", c.ttl)
	}

	return baseline, nil
}

// GetBaselinesForScope retrieves all baselines for a given scope.
// This method does not cache the result as it returns a list that may change.
func (c *BaselineCache) GetBaselinesForScope(
	ctx context.Context,
	scopeRef string,
) ([]*Baseline, error) {
	// For list queries, we don't cache as the list may change
	// and these queries are typically less frequent
	c.logger.V(vplogging.LogLevelDebug).Info("fetching baselines for scope (no cache)",
		"scopeRef", scopeRef)

	return c.provider.GetBaselinesForScope(ctx, scopeRef)
}

// InvalidateCache removes all entries from the cache.
// This can be called when the cache should be refreshed (e.g., after a baseline update).
func (c *BaselineCache) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldSize := len(c.cache)
	c.cache = make(map[string]*cacheEntry)

	c.logger.V(vplogging.LogLevelInfo).Info("baseline cache invalidated",
		"entriesRemoved", oldSize)
}

// InvalidateScope removes all cache entries for a specific scope.
func (c *BaselineCache) InvalidateScope(scopeRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for key := range c.cache {
		if getScopeFromCacheKey(key) == scopeRef {
			delete(c.cache, key)
			count++
		}
	}

	c.logger.V(vplogging.LogLevelInfo).Info("baseline cache invalidated for scope",
		"scopeRef", scopeRef,
		"entriesRemoved", count)
}

// Size returns the current number of entries in the cache.
func (c *BaselineCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// buildCacheKey creates a cache key from scopeRef and featureSet.
func buildCacheKey(scopeRef, featureSet string) string {
	return scopeRef + ":" + featureSet
}

// getScopeFromCacheKey extracts the scopeRef from a cache key.
func getScopeFromCacheKey(key string) string {
	// Find the first colon
	for i, c := range key {
		if c == ':' {
			return key[:i]
		}
	}
	return key
}

// CleanupExpired removes all expired entries from the cache.
// This should be called periodically to prevent memory leaks.
func (c *BaselineCache) CleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
			count++
		}
	}

	if count > 0 {
		c.logger.V(vplogging.LogLevelInfo).Info("cleaned up expired baseline cache entries",
			"entriesRemoved", count)
	}
}

// StartCleanupLoop starts a background goroutine that periodically cleans up expired entries.
// It returns a function that can be called to stop the cleanup loop.
func (c *BaselineCache) StartCleanupLoop(interval time.Duration) func() {
	if interval <= 0 {
		interval = c.ttl / 2
		if interval < time.Second {
			interval = time.Second
		}
	}

	stopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				c.CleanupExpired()
			}
		}
	}()

	return func() {
		close(stopChan)
	}
}
