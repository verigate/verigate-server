package middleware

import (
	"strings"

	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// WebAuth is an authentication middleware for web applications.
// This operates independently from the OAuth authentication.
func WebAuth(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Error(errors.Unauthorized("Missing authorization header"))
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Error(errors.Unauthorized("Invalid authorization header format"))
			c.Abort()
			return
		}

		userID, err := authService.ValidateAccessToken(parts[1])
		if err != nil {
			c.Error(errors.Unauthorized("Invalid token"))
			c.Abort()
			return
		}

		// Store user ID in context
		c.Set("user_id", userID)

		c.Next()
	}
}
