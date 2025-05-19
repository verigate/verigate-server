// Package client provides functionality for managing OAuth clients,
// including registration, configuration, and management.
package client

import (
	"net/http"
	"strconv"

	"github.com/verigate/verigate-server/internal/pkg/middleware"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// Handler manages HTTP requests related to OAuth client operations.
// It handles client creation, retrieval, updating, and deletion.
type Handler struct {
	service *Service
}

// NewHandler creates a new client handler instance.
// It initializes the handler with the provided service for business logic operations.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes sets up the client-related routes on the provided router group.
// All routes are protected with web authentication middleware.
// Routes include:
// - POST /clients - Create a new OAuth client
// - GET /clients - List all clients for the authenticated user
// - GET /clients/:id - Get a specific client by ID
// - PUT /clients/:id - Update a specific client
// - DELETE /clients/:id - Delete a specific client
func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	// All client endpoints require web authentication
	r.Use(middleware.WebAuth(h.service.authService))

	r.POST("", h.Create)
	r.GET("", h.List)
	r.GET("/:id", h.Get)
	r.PUT("/:id", h.Update)
	r.DELETE("/:id", h.Delete)
}

// Create handles requests to register a new OAuth client.
// It extracts client details from the JSON request body, validates them,
// and creates a new client associated with the authenticated user.
// Returns 201 Created on success with the created client in the response body.
func (h *Handler) Create(c *gin.Context) {
	var req CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat + ": " + err.Error()))
		return
	}

	userID := c.GetUint("user_id")
	client, err := h.service.Create(c.Request.Context(), userID, req)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusCreated, client)
}

// Get retrieves a specific OAuth client by its ID.
// It extracts the client ID from the URL path, validates it, and returns the client details.
// Returns 200 OK on success with the client in the response body.
// Returns 400 Bad Request if the ID is invalid, or 404 Not Found if the client doesn't exist.
func (h *Handler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidClientId))
		return
	}

	client, err := h.service.GetByID(c.Request.Context(), uint(id))
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, client)
}

// Update handles requests to modify an existing OAuth client.
// It extracts the client ID from the URL path and update data from the request body,
// then applies the changes if the authenticated user owns the client.
// Returns 204 No Content on successful update.
// Returns 400 Bad Request if the ID or request body is invalid,
// 403 Forbidden if the user doesn't own the client, or 404 Not Found if the client doesn't exist.
func (h *Handler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidClientId))
		return
	}

	var req UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidRequestFormat + ": " + err.Error()))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.Update(c.Request.Context(), uint(id), userID, req); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// Delete handles requests to remove an OAuth client.
// It extracts the client ID from the URL path and verifies ownership before deletion.
// Returns 204 No Content on successful deletion.
// Returns 400 Bad Request if the ID is invalid, 403 Forbidden if the user doesn't own the client,
// or 404 Not Found if the client doesn't exist.
func (h *Handler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.Error(errors.BadRequest(errors.ErrMsgInvalidClientId))
		return
	}

	userID := c.GetUint("user_id")
	if err := h.service.Delete(c.Request.Context(), uint(id), userID); err != nil {
		c.Error(err)
		return
	}

	c.Status(http.StatusNoContent)
}

// List retrieves all OAuth clients owned by the authenticated user with pagination.
// It extracts pagination parameters from query string and returns a paginated list of clients.
// Query parameters:
//   - page: The page number (default: 1)
//   - limit: Number of items per page (default: 10, max: 100)
//
// Returns 200 OK with the list of clients in the response body.
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
	clients, err := h.service.List(c.Request.Context(), userID, page, limit)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, clients)
}
