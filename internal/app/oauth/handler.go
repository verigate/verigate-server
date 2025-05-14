package oauth

import (
	"encoding/base64"
	"net/http"
	"strings"

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
	r.POST("/token", h.Token)
	r.POST("/revoke", h.Revoke)

	// OAuth protected endpoints
	oauthProtected := r.Group("")
	oauthProtected.Use(middleware.Auth())
	{
		oauthProtected.GET("/authorize", h.Authorize)
		oauthProtected.GET("/userinfo", h.UserInfo)
	}

	// Web app protected endpoints (consent screen)
	webProtected := r.Group("")
	webProtected.Use(middleware.WebAuth(h.service.authService))
	{
		webProtected.GET("/consent", h.ShowConsent)
		webProtected.POST("/consent", h.HandleConsent)
	}
}

func (h *Handler) Authorize(c *gin.Context) {
	var req AuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.redirectError(c, req.RedirectURI, req.State, "invalid_request", "Invalid request parameters")
		return
	}

	userID := c.GetUint("user_id")
	code, err := h.service.Authorize(c.Request.Context(), req, userID)

	if err != nil {
		// Check if consent is required
		if customErr, ok := err.(errors.CustomError); ok && customErr.Status == 302 {
			// Redirect to consent page
			c.Redirect(http.StatusFound, h.buildConsentURL(req))
			return
		}

		// Handle other errors
		h.redirectError(c, req.RedirectURI, req.State, "server_error", err.Error())
		return
	}

	// Build redirect URL with code
	redirectURL := h.buildRedirectURL(req.RedirectURI, code, req.State)
	c.Redirect(http.StatusFound, redirectURL)
}

func (h *Handler) Token(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request format",
		})
		return
	}

	// Get client credentials
	clientID, clientSecret, err := h.getClientCredentials(c, req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client authentication failed",
		})
		return
	}

	// Validate client if confidential
	if clientSecret != "" {
		client, err := h.service.ValidateClient(c.Request.Context(), clientID, clientSecret)
		if err != nil || client == nil {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "Client authentication failed",
			})
			return
		}
	} else {
		// Verify this is a public client
		isPublic, err := h.service.IsPublicClient(c.Request.Context(), clientID)
		if err != nil || !isPublic {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "Client authentication failed",
			})
			return
		}
	}

	// Set client ID in request
	req.ClientID = clientID

	token, err := h.service.Token(c.Request.Context(), req)
	if err != nil {
		if customErr, ok := err.(errors.CustomError); ok {
			c.JSON(customErr.Status, ErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: customErr.Message,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, token)
}

func (h *Handler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request format",
		})
		return
	}

	// Get client credentials
	clientID, _, err := h.getClientCredentials(c, TokenRequest{})
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client authentication failed",
		})
		return
	}

	if err := h.service.Revoke(c.Request.Context(), req, clientID); err != nil {
		// RFC 7009: Always return success
	}

	c.Status(http.StatusOK)
}

func (h *Handler) UserInfo(c *gin.Context) {
	userID := c.GetUint("user_id")

	userInfo, err := h.service.GetUserInfo(c.Request.Context(), userID)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

func (h *Handler) ShowConsent(c *gin.Context) {
	clientID := c.Query("client_id")
	scope := c.Query("scope")

	data, err := h.service.GetConsentPageData(c.Request.Context(), clientID, scope)
	if err != nil {
		c.Error(err)
		return
	}

	// In a real application, this would render a consent page template
	c.JSON(http.StatusOK, data)
}

func (h *Handler) HandleConsent(c *gin.Context) {
	type ConsentRequest struct {
		ClientID string `json:"client_id" binding:"required"`
		Scope    string `json:"scope" binding:"required"`
		Consent  bool   `json:"consent" binding:"required"`
	}

	var req ConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.BadRequest("Invalid request format"))
		return
	}

	userID := c.GetUint("user_id")

	if !req.Consent {
		// User denied consent
		c.JSON(http.StatusOK, gin.H{
			"redirect": h.buildErrorRedirect(c.Query("redirect_uri"), c.Query("state"), "access_denied", "User denied access"),
		})
		return
	}

	// Save consent
	if err := h.service.SaveConsent(c.Request.Context(), userID, req.ClientID, req.Scope); err != nil {
		c.Error(err)
		return
	}

	// Create authorization request to retry
	authReq := AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            req.ClientID,
		RedirectURI:         c.Query("redirect_uri"),
		Scope:               req.Scope,
		State:               c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}

	code, err := h.service.Authorize(c.Request.Context(), authReq, userID)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"redirect": h.buildRedirectURL(authReq.RedirectURI, code, authReq.State),
	})
}

// Helper methods

func (h *Handler) getClientCredentials(c *gin.Context, req TokenRequest) (string, string, error) {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
		credentials, err := base64.StdEncoding.DecodeString(authHeader[6:])
		if err != nil {
			return "", "", errors.BadRequest("Invalid basic auth format")
		}

		parts := strings.SplitN(string(credentials), ":", 2)
		if len(parts) != 2 {
			return "", "", errors.BadRequest("Invalid basic auth format")
		}

		return parts[0], parts[1], nil
	}

	// Fall back to form parameters
	clientID := req.ClientID
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}

	clientSecret := req.ClientSecret
	if clientSecret == "" {
		clientSecret = c.PostForm("client_secret")
	}

	if clientID == "" {
		return "", "", errors.BadRequest("Missing client_id")
	}

	return clientID, clientSecret, nil
}

func (h *Handler) buildRedirectURL(redirectURI, code, state string) string {
	separator := "?"
	if strings.Contains(redirectURI, "?") {
		separator = "&"
	}

	result := redirectURI + separator + "code=" + code
	if state != "" {
		result += "&state=" + state
	}

	return result
}

func (h *Handler) buildErrorRedirect(redirectURI, state, errorCode, errorDesc string) string {
	separator := "?"
	if strings.Contains(redirectURI, "?") {
		separator = "&"
	}

	result := redirectURI + separator + "error=" + errorCode
	if errorDesc != "" {
		result += "&error_description=" + strings.ReplaceAll(errorDesc, " ", "+")
	}
	if state != "" {
		result += "&state=" + state
	}

	return result
}

func (h *Handler) redirectError(c *gin.Context, redirectURI, state, errorCode, errorDesc string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:            errorCode,
			ErrorDescription: errorDesc,
		})
		return
	}

	c.Redirect(http.StatusFound, h.buildErrorRedirect(redirectURI, state, errorCode, errorDesc))
}

func (h *Handler) buildConsentURL(req AuthorizeRequest) string {
	params := []string{
		"client_id=" + req.ClientID,
		"redirect_uri=" + req.RedirectURI,
		"scope=" + req.Scope,
		"state=" + req.State,
	}

	if req.CodeChallenge != "" {
		params = append(params, "code_challenge="+req.CodeChallenge)
		params = append(params, "code_challenge_method="+req.CodeChallengeMethod)
	}

	return "/oauth/consent?" + strings.Join(params, "&")
}
