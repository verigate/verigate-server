// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"strings"

	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// WebAuth is an authentication middleware for web applications.
// This middleware validates JWT access tokens issued to web application users
// and operates independently from the OAuth 2.0 authentication system.
//
// The middleware:
// 1. Extracts the Authorization header from the request
// 2. Validates the bearer token format
// 3. Verifies the token signature and validity using the auth service
// 4. Sets the authenticated user ID in the request context for downstream handlers
//
// If authentication fails, the middleware aborts the request with an appropriate error.
func WebAuth(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Error(errors.Unauthorized("Missing authorization header"))
			c.Abort()
			return
		}

		// Validate Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Error(errors.Unauthorized("Invalid authorization header format"))
			c.Abort()
			return
		}

		// Validate token and extract user ID
		userID, err := authService.ValidateAccessToken(parts[1])
		if err != nil {
			c.Error(errors.Unauthorized("Invalid token"))
			c.Abort()
			return
		}

		// Store user ID in context for downstream handlers
		c.Set("user_id", userID)

		c.Next()
	}
}
