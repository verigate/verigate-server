// Package token provides functionality for OAuth token management.
package token

import (
	"net/http"
	"strconv"

	"github.com/verigate/verigate-server/internal/pkg/middleware"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// Handler manages HTTP requests related to access tokens.
type Handler struct {
	service *Service
}

// NewHandler creates a new token handler with the given service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers the token management routes on the provided router group.
// All routes are protected by web authentication.
func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	// All token endpoints require web authentication
	r.Use(middleware.WebAuth(h.service.authService))

	r.GET("", h.List)          // List user's tokens
	r.DELETE("/:id", h.Revoke) // Revoke a specific token
}

// List handles the GET request to list the authenticated user's access tokens.
// It supports pagination through query parameters.
//
// Route: GET /tokens
// Query parameters:
//   - page: Page number (default: 1)
//   - limit: Number of tokens per page (default: 10, max: 100)
func (h *Handler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	userID := c.GetUint("user_id")
	tokens, err := h.service.ListTokens(c.Request.Context(), userID, page, limit)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// Revoke handles the DELETE request to revoke a specific access token.
// The user can only revoke their own tokens.
//
// Route: DELETE /tokens/:id
// Path parameters:
//   - id: The ID of the token to revoke
func (h *Handler) Revoke(c *gin.Context) {
	tokenID := c.Param("id")
	if tokenID == "" {
		c.Error(errors.BadRequest("token ID is required"))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.RevokeToken(c.Request.Context(), tokenID, userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}
