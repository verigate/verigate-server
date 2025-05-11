package token

import (
	"net/http"
	"strconv"

	"github.com/verigate/verigate-server/internal/pkg/middleware"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	// All token endpoints require authentication
	r.Use(middleware.Auth())

	r.GET("", h.List)
	r.DELETE("/:id", h.Revoke)
}

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

func (h *Handler) Revoke(c *gin.Context) {
	tokenID := c.Param("id")
	userID := c.GetUint("user_id")

	if err := h.service.RevokeToken(c.Request.Context(), tokenID, userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}
