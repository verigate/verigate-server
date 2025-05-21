// Package main provides the entry point for the Verigate Server API.
// It initializes configuration, databases, services, and HTTP routes.
package main

import (
	"log"
	"time"

	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/app/client"
	"github.com/verigate/verigate-server/internal/app/oauth"
	"github.com/verigate/verigate-server/internal/app/scope"
	"github.com/verigate/verigate-server/internal/app/token"
	"github.com/verigate/verigate-server/internal/app/user"
	"github.com/verigate/verigate-server/internal/pkg/config"
	"github.com/verigate/verigate-server/internal/pkg/db/postgres"
	"github.com/verigate/verigate-server/internal/pkg/db/redis"
	"github.com/verigate/verigate-server/internal/pkg/middleware"
	"github.com/verigate/verigate-server/internal/pkg/utils/jwt"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// main is the entry point for the Verigate Server API.
// It initializes all components and starts the HTTP server.
func main() {
	// Configuration and logging
	config.Load()
	logger, err := setupLogger()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	sugar := logger.Sugar()

	// Initialize JWT keys
	if err := jwt.InitKeys(); err != nil {
		sugar.Fatalf("Failed to initialize JWT keys: %v", err)
	}

	// Database connections
	redisClient, err := redis.NewConnection()
	if err != nil {
		sugar.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	postgresDB, err := postgres.NewConnection()
	if err != nil {
		sugar.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer postgresDB.Close()

	// Repositories
	userRepo := postgres.NewUserRepository(postgresDB)
	clientRepo := postgres.NewClientRepository(postgresDB)
	oauthRepo := postgres.NewOAuthRepository(postgresDB)
	tokenRepo := postgres.NewTokenRepository(postgresDB)
	scopeRepo := postgres.NewScopeRepository(postgresDB)
	cacheRepo := redis.NewCacheRepository(redisClient)
	authRepo := redis.NewAuthRepository(redisClient) // Added

	// Services
	authService := auth.NewService(authRepo)                    // Added
	userService := user.NewService(userRepo, authService)       // Modified
	clientService := client.NewService(clientRepo, authService) // Modified
	scopeService := scope.NewService(scopeRepo)
	tokenService := token.NewService(tokenRepo, cacheRepo, authService)                                              // Modified
	oauthService := oauth.NewService(oauthRepo, userService, clientService, tokenService, scopeService, authService) // Modified

	// Handlers
	userHandler := user.NewHandler(userService)
	clientHandler := client.NewHandler(clientService)
	tokenHandler := token.NewHandler(tokenService)
	oauthHandler := oauth.NewHandler(oauthService)

	// Router setup
	router := setupRouter(logger, userHandler, clientHandler, tokenHandler, oauthHandler)

	// Start server
	sugar.Infof("Starting server on port %s", config.AppConfig.AppPort)
	if err := router.Run(":" + config.AppConfig.AppPort); err != nil {
		sugar.Fatalf("Failed to start server: %v", err)
	}
}

// setupLogger initializes and configures the application logger.
// It creates either a production or development logger based on the application environment.
// Returns the configured zap logger and any error encountered during setup.
func setupLogger() (*zap.Logger, error) {
	var zapConfig zap.Config

	if config.AppConfig.Environment == "production" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
	}

	return zapConfig.Build()
}

// setupRouter configures the HTTP router with all routes and middleware.
// It registers all handlers, sets up middleware for logging, error handling, rate limiting,
// CORS, and recovery from panics.
// Returns the configured gin engine ready to serve HTTP requests.
func setupRouter(
	logger *zap.Logger,
	userHandler *user.Handler,
	clientHandler *client.Handler,
	tokenHandler *token.Handler,
	oauthHandler *oauth.Handler,
) *gin.Engine {
	if config.AppConfig.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Middleware
	router.Use(middleware.RequestLogger(logger))
	router.Use(middleware.Recovery(logger))
	router.Use(middleware.CORS())
	router.Use(middleware.ErrorHandler())

	// Rate limiting setup
	rateLimiter := middleware.NewRedisRateLimiter(
		redis.GetClient(),
		"rate_limit:",
		config.AppConfig.RateLimitRequestsPerMinute,
		60, // 1 minute window
	)

	// IP control setup
	ipControl := middleware.NewIPControl(
		config.AppConfig.IPWhitelist,
		config.AppConfig.IPBlacklist,
	)

	// Apply middleware
	router.Use(middleware.IPControlMiddleware(ipControl))

	// API routes
	api := router.Group("/api/v1")
	{
		// OAuth endpoints (with rate limiting)
		oauthGroup := api.Group("/oauth")
		oauthGroup.Use(middleware.RateLimitMiddleware(rateLimiter))
		{
			oauthHandler.RegisterRoutes(oauthGroup)
		}

		// User endpoints
		userGroup := api.Group("/users")
		{
			userHandler.RegisterRoutes(userGroup)
		}

		// Client endpoints
		clientGroup := api.Group("/clients")
		{
			clientHandler.RegisterRoutes(clientGroup)
		}

		// Token management endpoints
		tokenGroup := api.Group("/tokens")
		{
			tokenHandler.RegisterRoutes(tokenGroup)
		}
	}

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
			"time":   time.Now().Unix(),
		})
	})

	return router
}
