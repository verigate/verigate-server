// Package redis provides Redis connection and repository implementations
// for caching and ephemeral data storage in the Verigate Server application.
package redis

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-redis/redis/v8"
	"github.com/verigate/verigate-server/internal/pkg/config"
)

// client is the shared Redis client instance used across the application
var client *redis.Client

// NewConnection establishes a new Redis connection using configuration settings.
// It initializes the Redis client, validates the connection with a ping,
// and stores the client in a package-level variable for later access.
// Returns the Redis client or an error if the connection fails.
func NewConnection() (*redis.Client, error) {
	db, err := strconv.Atoi(config.AppConfig.RedisDB)
	if err != nil {
		db = 0
	}

	client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.AppConfig.RedisHost, config.AppConfig.RedisPort),
		Password: config.AppConfig.RedisPassword,
		DB:       db,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return client, nil
}

// GetClient returns the shared Redis client instance.
// This allows reusing the same connection throughout the application.
func GetClient() *redis.Client {
	return client
}
