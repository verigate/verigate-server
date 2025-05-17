// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
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
		// Extract bearer token from Authorization header
		tokenString, ok := extractBearerToken(c)
		if !ok {
			return // Error already handled in the function
		}

		// Validate token and extract user ID
		userID, err := authService.ValidateAccessToken(tokenString)
		if err != nil {
			c.Error(errors.Unauthorized(ErrMsgInvalidToken))
			c.Abort()
			return
		}

		// Store user ID in context for downstream handlers
		c.Set(ContextKeyUserID, userID)

		c.Next()
	}
}
