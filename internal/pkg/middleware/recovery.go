// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Recovery creates a middleware that recovers from any panics in subsequent handlers.
// It logs the panic details with the provided logger and returns a standardized error response.
// This middleware should be added early in the middleware chain to catch panics from all handlers.
func Recovery(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("panic recovered",
					zap.Any("error", err),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
					zap.String("ip", c.ClientIP()),
				)

				c.JSON(http.StatusInternalServerError, gin.H{
					"error":             "internal_server_error",
					"error_description": "An unexpected error occurred",
				})
				c.Abort()
			}
		}()

		c.Next()
	}
}

// RequestLogger creates a middleware that logs details about each request.
// It captures the request method, path, status code, response time, client IP,
// user agent, and number of errors encountered during request processing.
// This middleware provides valuable information for monitoring and debugging.
func RequestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Log request details
		logger.Info("request processed",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.Int("errors", len(c.Errors)),
		)
	}
}
