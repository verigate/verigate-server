// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/jwt"

	"github.com/gin-gonic/gin"
)

// Auth is an authentication middleware for OAuth APIs.
// This middleware validates JWT tokens issued through the OAuth 2.0 flow
// and is primarily used for securing the OAuth API endpoints.
//
// The middleware:
// 1. Extracts the Authorization header from the request
// 2. Validates the bearer token format
// 3. Verifies the token signature and validity using the JWT utility
// 4. Sets the authenticated user ID and claims in the request context
//
// If authentication fails, the middleware aborts the request with an appropriate error.
func Auth() gin.HandlerFunc {
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

		// Validate token and extract claims
		claims, err := jwt.ValidateToken(parts[1])
		if err != nil {
			c.Error(errors.Unauthorized("Invalid token"))
			c.Abort()
			return
		}

		// Store user ID and claims in context for downstream handlers
		c.Set("user_id", claims.UserID)
		c.Set("claims", claims)

		c.Next()
	}
}
