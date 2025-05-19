// Package user provides functionality for user account management including
// registration, authentication, profile management, and session handling.
package user

import (
	"net/http"

	"github.com/verigate/verigate-server/internal/pkg/middleware"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// Handler manages HTTP requests related to user operations.
// It handles user registration, login, profile management, and authentication.
type Handler struct {
	service *Service
}

// NewHandler creates a new user handler instance.
// It initializes the handler with the provided service for user operations.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes sets up the user-related routes on the provided router group.
// Routes are organized into two categories:
// - Public endpoints: Registration, login, and token refresh
// - Protected endpoints: User profile management, requiring authentication
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

// Register handles user account creation requests.
// It validates the registration input, creates a new user account,
// and returns the created user details on success.
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat))
		return
	}

	user, err := h.service.Register(c.Request.Context(), req)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Login handles user authentication requests.
// It validates credentials, records login metadata like IP address and user agent,
// and returns authentication tokens on successful login.
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat))
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

// RefreshToken handles token refresh requests.
// It validates the provided refresh token, checks if it's still valid,
// and issues a new access token and refresh token pair.
// This allows extending the user session without requiring re-authentication.
func (h *Handler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat))
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

// GetMe retrieves the authenticated user's profile information.
// It uses the user_id extracted during authentication to fetch the user details.
// This endpoint is protected and only accessible to authenticated users.
func (h *Handler) GetMe(c *gin.Context) {
	userID := c.GetUint("user_id")

	user, err := h.service.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateMe handles requests to update the authenticated user's profile information.
// It validates the update request and applies the changes to the user's profile.
// This endpoint is protected and only accessible to authenticated users.
func (h *Handler) UpdateMe(c *gin.Context) {
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.Update(c.Request.Context(), userID, req); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// ChangePassword handles requests to update a user's password.
// It validates the current password before allowing the change to a new password.
// This endpoint is protected and only accessible to authenticated users.
func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.ChangePassword(c.Request.Context(), userID, req); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// DeleteMe handles requests to delete a user's account.
// It permanently removes the user account and all associated data.
// This endpoint is protected and only accessible to authenticated users.
func (h *Handler) DeleteMe(c *gin.Context) {
	userID := c.GetUint("user_id")
	if err := h.service.Delete(c.Request.Context(), userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// Logout handles user logout requests by revoking all active refresh tokens.
// This effectively terminates all active sessions for the user.
// This endpoint is protected and only accessible to authenticated users.
func (h *Handler) Logout(c *gin.Context) {
	userID := c.GetUint("user_id")

	if err := h.service.Logout(c.Request.Context(), userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}
