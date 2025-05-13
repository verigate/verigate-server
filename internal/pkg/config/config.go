package config

import (
	"os"
	"strconv"
	"strings"
)

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

var AppConfig Config

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

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("missing required environment variable: " + key)
	}
	return value
}

func parseIPList(ips string) []string {
	if ips == "" {
		return []string{}
	}
	return strings.Split(ips, ",")
}
