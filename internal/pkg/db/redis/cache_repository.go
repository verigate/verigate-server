// Package redis provides Redis connection and repository implementations
// for caching and ephemeral data storage in the Verigate Server application.
package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
)

// cacheRepository implements a generic cache using Redis.
// It provides methods for storing, retrieving, and deleting
// arbitrary data with automatic JSON serialization.
type cacheRepository struct {
	client *redis.Client
}

// NewCacheRepository creates a new cache repository instance with the provided Redis client.
// This repository is used for temporary data storage with configurable expiration times.
func NewCacheRepository(client *redis.Client) *cacheRepository {
	return &cacheRepository{client: client}
}

// Set stores a value in the cache with the specified key and expiration time.
// The value is automatically serialized to JSON before storage.
// Returns an error if serialization or storage fails.
func (r *cacheRepository) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, jsonData, expiration).Err()
}

// Get retrieves a value from the cache by its key.
// Returns the serialized JSON value as a string and any error that occurred.
// A redis.Nil error is returned if the key doesn't exist.
func (r *cacheRepository) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// Delete removes a value from the cache by its key.
// Returns an error if the deletion fails.
func (r *cacheRepository) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}
