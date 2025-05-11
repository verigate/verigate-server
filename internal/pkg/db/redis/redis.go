package redis

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-redis/redis/v8"
	"github.com/verigate/verigate-server/internal/pkg/config"
)

var client *redis.Client

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

func GetClient() *redis.Client {
	return client
}
