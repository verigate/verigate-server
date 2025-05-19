// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// ErrorHandler creates a middleware that handles API errors in a consistent manner.
// It transforms error objects attached to the request context into standardized API responses.
// This middleware should be added early in the middleware chain to catch all errors.
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Execute the request handlers first
		c.Next()

		// Check if there are any errors
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err

			// Handle CustomError types with proper status codes and details
			if customErr, ok := err.(errors.CustomError); ok {
				response := gin.H{
					"error": customErr.Message,
				}

				// Add error details if available
				if customErr.Details != nil {
					response["error_description"] = customErr.Details
				}

				c.JSON(customErr.Status, response)
				return
			}

			// Handle unknown error types with a generic 500 response
			c.JSON(500, gin.H{
				"error":             errors.ErrMsgInternalServerError,
				"error_description": errors.ErrMsgUnexpectedError,
			})
		}
	}
}
