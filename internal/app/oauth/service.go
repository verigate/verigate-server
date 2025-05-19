package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/app/client"
	"github.com/verigate/verigate-server/internal/app/scope"
	"github.com/verigate/verigate-server/internal/app/token"
	"github.com/verigate/verigate-server/internal/app/user"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/pkce"
)

type Service struct {
	oauthRepo     Repository
	userService   *user.Service
	clientService *client.Service
	tokenService  *token.Service
	scopeService  *scope.Service
	authService   *auth.Service
}

func NewService(
	oauthRepo Repository,
	userService *user.Service,
	clientService *client.Service,
	tokenService *token.Service,
	scopeService *scope.Service,
	authService *auth.Service,
) *Service {
	return &Service{
		oauthRepo:     oauthRepo,
		userService:   userService,
		clientService: clientService,
		tokenService:  tokenService,
		scopeService:  scopeService,
		authService:   authService,
	}
}

func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest, userID uint) (string, error) {
	// Validate response type
	if req.ResponseType != "code" {
		return "", errors.BadRequest(errors.ErrMsgUnsupportedResponseType)
	}

	// Validate client
	client, err := s.clientService.GetByClientID(ctx, req.ClientID)
	if err != nil {
		return "", err
	}
	if client == nil || !client.IsActive {
		return "", errors.BadRequest(errors.ErrMsgInvalidClient)
	}

	// Validate redirect URI
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == req.RedirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		return "", errors.BadRequest(errors.ErrMsgInvalidRedirectUri)
	}

	// Validate PKCE
	if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "plain" && req.CodeChallengeMethod != "S256" {
		return "", errors.BadRequest(errors.ErrMsgInvalidCodeChallengeMethod)
	}

	// Validate and normalize scope
	requestedScope := req.Scope
	if requestedScope == "" {
		requestedScope = "profile" // Default scope
	}

	validScope, err := s.scopeService.ValidateScope(ctx, requestedScope, client.Scope)
	if err != nil || !validScope {
		return "", errors.BadRequest(errors.ErrMsgInvalidScope)
	}

	// Check if consent is needed
	if s.needsConsent(ctx, userID, req.ClientID, requestedScope) {
		// Return indicator that consent is needed (to be handled by the handler)
		return "", errors.New(302, "consent_required")
	}

	// Generate authorization code
	code, err := s.generateAuthorizationCode()
	if err != nil {
		return "", errors.Internal(errors.ErrMsgFailedToGenerateAuthCode)
	}

	// Save authorization code
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               requestedScope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
		IsUsed:              false,
	}

	if err := s.oauthRepo.SaveAuthorizationCode(ctx, authCode); err != nil {
		return "", errors.Internal(errors.ErrMsgFailedToSaveAuthCode)
	}

	return code, nil
}

func (s *Service) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, req)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, req)
	default:
		return nil, errors.BadRequest(errors.ErrMsgUnsupportedGrantType)
	}
}

func (s *Service) Revoke(ctx context.Context, req RevokeRequest, clientID string) error {
	if req.TokenTypeHint == "access_token" || req.TokenTypeHint == "" {
		err := s.tokenService.RevokeAccessToken(ctx, req.Token, clientID)
		if err == nil {
			return nil
		}
	}

	if req.TokenTypeHint == "refresh_token" || req.TokenTypeHint == "" {
		err := s.tokenService.RevokeRefreshToken(ctx, req.Token, clientID)
		if err == nil {
			return nil
		}
	}

	// RFC 7009: Return success even if token was not found
	return nil
}

func (s *Service) GetUserInfo(ctx context.Context, userID uint) (*UserInfoResponse, error) {
	user, err := s.userService.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &UserInfoResponse{
		Sub:               strconv.FormatUint(uint64(user.ID), 10),
		Name:              user.Username,
		Email:             user.Email,
		EmailVerified:     user.IsVerified,
		PreferredUsername: user.Username,
	}, nil
}

func (s *Service) SaveConsent(ctx context.Context, userID uint, clientID, scope string) error {
	consent, _ := s.oauthRepo.FindUserConsent(ctx, userID, clientID)

	if consent != nil {
		consent.Scope = scope
		consent.UpdatedAt = time.Now()
		return s.oauthRepo.UpdateUserConsent(ctx, consent)
	}

	consent = &UserConsent{
		UserID:    userID,
		ClientID:  clientID,
		Scope:     scope,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.oauthRepo.SaveUserConsent(ctx, consent)
}

func (s *Service) GetConsentPageData(ctx context.Context, clientID, scope string) (*ConsentPageData, error) {
	client, err := s.clientService.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(scope, " ")

	return &ConsentPageData{
		ClientName:     client.ClientName,
		ClientID:       clientID,
		RequestedScope: scope,
		ScopeList:      scopes,
	}, nil
}

// Private helper methods

func (s *Service) handleAuthorizationCodeGrant(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	// Validate required parameters
	if req.Code == "" || req.RedirectURI == "" {
		return nil, errors.BadRequest(errors.ErrMsgInvalidRequest)
	}

	// Get and validate authorization code
	authCode, err := s.oauthRepo.FindAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToGetAuthCode)
	}
	if authCode == nil {
		return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
	}

	// Validate code hasn't been used
	if authCode.IsUsed {
		// Security: revoke all tokens associated with this code
		s.tokenService.RevokeTokensByAuthCode(ctx, req.Code)
		return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
	}

	// Validate code hasn't expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
	}

	// Validate client
	if authCode.ClientID != req.ClientID {
		return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
	}

	// Validate redirect URI
	if authCode.RedirectURI != req.RedirectURI {
		return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
	}

	// Validate PKCE if used
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
		}

		if !pkce.VerifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, errors.BadRequest(errors.ErrMsgInvalidGrant)
		}
	}

	// Mark code as used
	if err := s.oauthRepo.MarkCodeAsUsed(ctx, req.Code); err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToMarkCodeAsUsed)
	}

	// Generate tokens
	tokenResp, err := s.tokenService.CreateTokens(ctx, authCode.UserID, authCode.ClientID, authCode.Scope, req.Code)
	if err != nil {
		return nil, err
	}

	// Convert token.TokenCreateResponse to TokenResponse
	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
	}, nil
}

func (s *Service) handleRefreshTokenGrant(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, errors.BadRequest(errors.ErrMsgInvalidRequest)
	}

	tokenResp, err := s.tokenService.RefreshTokens(ctx, req.RefreshToken, req.ClientID, req.Scope)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
	}, nil
}

func (s *Service) needsConsent(ctx context.Context, userID uint, clientID, scope string) bool {
	consent, err := s.oauthRepo.FindUserConsent(ctx, userID, clientID)
	if err != nil || consent == nil {
		return true
	}

	// Check if requested scope is within already consented scope
	requestedScopes := strings.Split(scope, " ")
	consentedScopes := strings.Split(consent.Scope, " ")

	for _, requested := range requestedScopes {
		found := false
		for _, consented := range consentedScopes {
			if requested == consented {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	return false
}

func (s *Service) generateAuthorizationCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Additional methods for client validation
func (s *Service) ValidateClient(ctx context.Context, clientID, clientSecret string) (*client.Client, error) {
	return s.clientService.ValidateClient(ctx, clientID, clientSecret)
}

func (s *Service) IsPublicClient(ctx context.Context, clientID string) (bool, error) {
	client, err := s.clientService.GetByClientID(ctx, clientID)
	if err != nil {
		return false, err
	}
	if client == nil {
		return false, errors.NotFound(errors.ErrMsgClientNotFound)
	}
	return !client.IsConfidential, nil
}
