package user

import (
	"net/http"

	"github.com/verigate/verigate-server/internal/pkg/middleware"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	// Public endpoints
	r.POST("/register", h.Register)
	r.POST("/login", h.Login)
	r.POST("/refresh-token", h.RefreshToken) // Added

	// Protected endpoints
	protected := r.Group("")
	protected.Use(middleware.WebAuth(h.service.authService)) // Changed to WebAuth
	{
		protected.GET("/me", h.GetMe)
		protected.PUT("/me", h.UpdateMe)
		protected.PUT("/me/password", h.ChangePassword)
		protected.DELETE("/me", h.DeleteMe)
		protected.POST("/logout", h.Logout) // Added
	}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest("Invalid request format"))
		return
	}

	user, err := h.service.Register(c.Request.Context(), req)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest("Invalid request format"))
		return
	}

	// Extract user agent and IP address
	userAgent := c.Request.UserAgent()
	ipAddress := c.ClientIP()

	response, err := h.service.Login(c.Request.Context(), req, userAgent, ipAddress)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, response)
}

// RefreshToken handles token refresh requests
func (h *Handler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest("Invalid request format"))
		return
	}

	// Extract user agent and IP address
	userAgent := c.Request.UserAgent()
	ipAddress := c.ClientIP()

	response, err := h.service.RefreshToken(c.Request.Context(), req.RefreshToken, userAgent, ipAddress)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) GetMe(c *gin.Context) {
	userID := c.GetUint("user_id")

	user, err := h.service.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *Handler) UpdateMe(c *gin.Context) {
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest("Invalid request format"))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.Update(c.Request.Context(), userID, req); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest("Invalid request format"))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.ChangePassword(c.Request.Context(), userID, req); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *Handler) DeleteMe(c *gin.Context) {
	userID := c.GetUint("user_id")
	if err := h.service.Delete(c.Request.Context(), userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// Logout handles user logout by revoking all refresh tokens
func (h *Handler) Logout(c *gin.Context) {
	userID := c.GetUint("user_id")

	if err := h.service.Logout(c.Request.Context(), userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}
