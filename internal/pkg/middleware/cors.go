// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that handles Cross-Origin Resource Sharing (CORS).
// This middleware allows web applications running on different domains to
// interact with the API securely.
//
// The configuration:
// - Allows requests from any origin (*)
// - Supports common HTTP methods (GET, POST, PUT, PATCH, DELETE)
// - Allows Authorization and content headers
// - Enables credentials (cookies, authorization headers)
// - Sets preflight cache to 12 hours
func CORS() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     []string{"*"},                                                         // Allow any origin
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},  // Standard HTTP methods
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"}, // Common headers
		ExposeHeaders:    []string{"Content-Length"},                                            // Expose Content-Length header
		AllowCredentials: true,                                                                  // Allow sending cookies
		MaxAge:           12 * time.Hour,                                                        // Cache preflight for 12 hours
	})
}
