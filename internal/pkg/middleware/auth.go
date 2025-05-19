// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/jwt"

	"github.com/gin-gonic/gin"
)

const (
	// AuthHeaderName is the HTTP header name for authorization
	AuthHeaderName = "Authorization"

	// AuthHeaderPrefix is the prefix for bearer token authorization scheme
	AuthHeaderPrefix = "Bearer"

	// Error messages for authentication failures
	ErrMsgMissingAuthHeader = "missing authorization header"
	ErrMsgInvalidAuthFormat = "invalid authorization header format"
	ErrMsgInvalidToken      = "invalid token"

	// Context keys for authentication data
	ContextKeyUserID = "user_id" // Must match jwt.ClaimKeyUserID
	ContextKeyClaims = "claims"
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
		// Extract bearer token from Authorization header
		tokenString, ok := extractBearerToken(c)
		if !ok {
			return // Error already handled in the function
		}

		// Validate token and extract claims
		claims, err := jwt.ValidateToken(tokenString)
		if err != nil {
			c.Error(errors.Unauthorized(ErrMsgInvalidToken))
			c.Abort()
			return
		}

		// Store user ID and claims in context for downstream handlers
		c.Set(ContextKeyUserID, claims.UserID)
		c.Set(ContextKeyClaims, claims)

		c.Next()
	}
}

// extractBearerToken extracts the bearer token from the Authorization header.
// It returns the token string and a boolean indicating if extraction was successful.
// If extraction fails, it aborts the request with an appropriate error.
func extractBearerToken(c *gin.Context) (string, bool) {
	// Extract Authorization header
	authHeader := c.GetHeader(AuthHeaderName)
	if authHeader == "" {
		c.Error(errors.Unauthorized(ErrMsgMissingAuthHeader))
		c.Abort()
		return "", false
	}

	// Validate Bearer token format
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != AuthHeaderPrefix {
		c.Error(errors.Unauthorized(ErrMsgInvalidAuthFormat))
		c.Abort()
		return "", false
	}

	return parts[1], true
}
