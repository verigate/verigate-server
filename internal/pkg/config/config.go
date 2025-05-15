// Package config provides application configuration functionality.
// It handles loading configuration values from environment variables.
package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all configuration values for the application.
// Most values are loaded from environment variables with sensible defaults.
type Config struct {
	AppPort                    string
	Environment                string
	JWTPrivateKey              string
	JWTPublicKey               string
	JWTAccessExpiry            string
	JWTRefreshExpiry           string
	PostgresHost               string
	PostgresPort               string
	PostgresDB                 string
	PostgresUser               string
	PostgresPassword           string
	RedisHost                  string
	RedisPort                  string
	RedisPassword              string
	RedisDB                    string
	RateLimitRequestsPerMinute int
	IPWhitelist                []string
	IPBlacklist                []string
}

// AppConfig is the global configuration instance for the application.
// It should be initialized with Load() before use.
var AppConfig Config

// Load initializes the global AppConfig by reading configuration values
// from environment variables. Any required environment variables that
// are missing will cause the application to panic.
func Load() {
	AppConfig = Config{
		AppPort:          getEnv("APP_PORT", "8080"),
		Environment:      getEnv("ENVIRONMENT", "development"),
		JWTPrivateKey:    mustGetEnv("JWT_PRIVATE_KEY"),
		JWTPublicKey:     mustGetEnv("JWT_PUBLIC_KEY"),
		JWTAccessExpiry:  getEnv("JWT_ACCESS_EXPIRY", "15m"),
		JWTRefreshExpiry: getEnv("JWT_REFRESH_EXPIRY", "168h"),
		PostgresHost:     getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:     getEnv("POSTGRES_PORT", "5432"),
		PostgresDB:       getEnv("POSTGRES_DB", "oauth_server"),
		PostgresUser:     getEnv("POSTGRES_USER", "postgres"),
		PostgresPassword: mustGetEnv("POSTGRES_PASSWORD"),
		RedisHost:        getEnv("REDIS_HOST", "localhost"),
		RedisPort:        getEnv("REDIS_PORT", "6379"),
		RedisPassword:    getEnv("REDIS_PASSWORD", ""),
		RedisDB:          getEnv("REDIS_DB", "0"),
	}

	// Parse rate limit
	rateLimit, err := strconv.Atoi(getEnv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
	if err != nil {
		rateLimit = 60
	}
	AppConfig.RateLimitRequestsPerMinute = rateLimit

	// Parse IP lists
	AppConfig.IPWhitelist = parseIPList(getEnv("IP_WHITELIST", ""))
	AppConfig.IPBlacklist = parseIPList(getEnv("IP_BLACKLIST", ""))
}

// getEnv retrieves a value from environment variables with a fallback default.
// If the environment variable is not set or is empty, the default value is returned.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// mustGetEnv retrieves a required value from environment variables.
// If the environment variable is not set or is empty, the function panics.
// This should be used only for configuration values that are essential
// for the application to function.
func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("missing required environment variable: " + key)
	}
	return value
}

// parseIPList converts a comma-separated string of IP addresses into a string slice.
// This is used for parsing IP whitelist and blacklist environment variables.
// Returns an empty slice if the input string is empty.
func parseIPList(ips string) []string {
	if ips == "" {
		return []string{}
	}
	return strings.Split(ips, ",")
}
