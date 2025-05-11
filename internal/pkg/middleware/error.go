package middleware

import (
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			if customErr, ok := err.(errors.CustomError); ok {
				c.JSON(customErr.Status, gin.H{
					"error":             customErr.Message,
					"error_description": customErr.Details,
				})
				return
			}

			c.JSON(500, gin.H{
				"error":             "internal_server_error",
				"error_description": "An unexpected error occurred",
			})
		}
	}
}
