package middleware

import (
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/jwt"

	"github.com/gin-gonic/gin"
)

func Auth() gin.HandlerFunc {
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

		claims, err := jwt.ValidateToken(parts[1])
		if err != nil {
			c.Error(errors.Unauthorized("Invalid token"))
			c.Abort()
			return
		}

		// Set user ID in context for downstream handlers
		c.Set("user_id", claims.UserID)
		c.Set("claims", claims)

		c.Next()
	}
}
