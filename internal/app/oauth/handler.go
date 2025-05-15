// Package oauth provides functionality for implementing OAuth 2.0 authorization flows,
// including authorization code, implicit, password, and client credentials.
package oauth

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/middleware"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// Handler manages HTTP requests related to OAuth authorization flows.
// It handles authorization, token issuance, revocation, and user information endpoints.
type Handler struct {
	service *Service
}

// NewHandler creates a new OAuth handler instance.
// It initializes the handler with the provided service for OAuth operations.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes sets up the OAuth-related routes on the provided router group.
// Routes are organized into three categories:
// - Public endpoints: Token issuance and revocation
// - OAuth protected endpoints: Require OAuth token authorization
// - Web app protected endpoints: Require web authentication for consent screens
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

// Authorize handles the OAuth authorization request.
// This is the entry point for the OAuth authorization code flow.
// It validates the request, checks if user consent is needed,
// and either issues an authorization code or redirects to the consent page.
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

// Token handles the OAuth token issuance endpoint.
// This endpoint supports various grant types including authorization_code,
// refresh_token, client_credentials, and password grants.
// It validates the client credentials and issues access and refresh tokens.
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

// Revoke handles token revocation as specified in RFC 7009.
// It allows clients to notify the authorization server that a
// previously obtained refresh or access token is no longer needed.
// This endpoint always returns success even if the token was not found.
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

// UserInfo implements the OpenID Connect UserInfo endpoint.
// It returns claims about the authenticated user based on the scope
// of the access token used to access this endpoint.
// The endpoint is OAuth 2.0 protected and requires a valid access token.
func (h *Handler) UserInfo(c *gin.Context) {
	userID := c.GetUint("user_id")

	userInfo, err := h.service.GetUserInfo(c.Request.Context(), userID)
	if err != nil {
		c.Error(err)
		return
	}

	c.JSON(http.StatusOK, userInfo)
}

// ShowConsent displays the OAuth consent page to the user.
// This page shows the application name, requested scopes, and allows the user
// to approve or deny the authorization request.
// In a production environment, this would typically render an HTML template.
// ShowConsent displays the consent page to the user.
// This page presents information about the client application requesting access
// and the specific permissions (scopes) being requested.
// The user can then approve or deny these permission requests.
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

// HandleConsent processes the user's consent decision for an OAuth authorization request.
// It receives the user's approval or rejection of the requested permissions
// and either proceeds with the authorization flow or returns an access_denied error.
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

// getClientCredentials extracts client credentials from the request.
// It first tries to get credentials from the Authorization header using HTTP Basic auth,
// and falls back to form parameters if not found in the header.
// Returns the client ID, client secret (may be empty for public clients), and any error that occurred.
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

// buildRedirectURL constructs the OAuth callback URL with authorization code and state parameters.
// It handles adding the appropriate query string separator (? or &) depending on whether
// the redirect URI already contains query parameters.
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

// buildErrorRedirect constructs an OAuth error redirect URL according to the OAuth 2.0 specification.
// It includes the error code, error description (with spaces replaced by '+'), and preserves the state parameter.
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

// redirectError handles OAuth error responses according to the OAuth 2.0 specification.
// If a valid redirect URI is provided, it redirects the client with error parameters in the query string.
// If no redirect URI is available, it returns a JSON error response directly.
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

// buildConsentURL constructs the URL for the consent page, preserving all the
// parameters from the original authorization request to use after consent.
// This ensures the OAuth flow can continue with the same parameters once
// the user has provided their consent decision.
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
