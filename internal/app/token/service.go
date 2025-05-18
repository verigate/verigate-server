// Package token provides functionality for OAuth token management,
// including access tokens and refresh tokens.
package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/verigate/verigate-server/internal/app/auth"
	"github.com/verigate/verigate-server/internal/pkg/config"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/hash"
	jwtutil "github.com/verigate/verigate-server/internal/pkg/utils/jwt"
)

// Constants
const (
	TokenTypeBearer = "Bearer" // Bearer token type for Authorization header

	// Cache key prefixes
	CacheKeyAccessToken = "access_token:" // Prefix for access token cache keys
)

// CacheRepository defines the interface for token caching operations.
type CacheRepository interface {
	// Set stores a value in the cache with the specified expiration
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error

	// Get retrieves a value from the cache
	Get(ctx context.Context, key string) (string, error)

	// Delete removes a value from the cache
	Delete(ctx context.Context, key string) error
}

// Service handles token-related operations including creation, validation,
// and revocation of access and refresh tokens.
type Service struct {
	tokenRepo     Repository
	cacheRepo     CacheRepository
	authService   *auth.Service
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewService creates a new token service instance with the necessary dependencies.
func NewService(tokenRepo Repository, cacheRepo CacheRepository, authService *auth.Service) *Service {
	// Parse JWT keys
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.AppConfig.JWTPrivateKey))
	if err != nil {
		panic("failed to parse private key: " + err.Error())
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(config.AppConfig.JWTPublicKey))
	if err != nil {
		panic("failed to parse public key: " + err.Error())
	}

	// Parse expiry durations
	accessExpiry, err := time.ParseDuration(config.AppConfig.JWTAccessExpiry)
	if err != nil {
		panic("invalid access token expiry: " + err.Error())
	}

	refreshExpiry, err := time.ParseDuration(config.AppConfig.JWTRefreshExpiry)
	if err != nil {
		panic("invalid refresh token expiry: " + err.Error())
	}

	return &Service{
		tokenRepo:     tokenRepo,
		cacheRepo:     cacheRepo,
		authService:   authService,
		privateKey:    privateKey,
		publicKey:     publicKey,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

// CreateTokens generates new access and refresh tokens for a user.
// It stores the tokens in the database and returns them to the client.
func (s *Service) CreateTokens(ctx context.Context, userID uint, clientID, scope, authCode string) (*TokenCreateResponse, error) {
	// Generate access token
	accessToken, accessTokenID, err := s.createAccessToken(userID, clientID, scope)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, refreshTokenID, err := s.createRefreshToken()
	if err != nil {
		return nil, err
	}

	// Hash tokens for storage
	accessTokenHash, err := hash.HashPassword(accessToken)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToHashAccessToken)
	}

	refreshTokenHash, err := hash.HashPassword(refreshToken)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToHashRefreshToken)
	}

	// Save tokens
	accessTokenModel := &AccessToken{
		TokenID:   accessTokenID,
		TokenHash: accessTokenHash,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(s.accessExpiry),
		CreatedAt: time.Now(),
		IsRevoked: false,
	}

	if err := s.tokenRepo.SaveAccessToken(ctx, accessTokenModel); err != nil {
		return nil, err
	}

	refreshTokenModel := &RefreshToken{
		TokenID:       refreshTokenID,
		TokenHash:     refreshTokenHash,
		AccessTokenID: accessTokenID,
		ClientID:      clientID,
		UserID:        userID,
		Scope:         scope,
		ExpiresAt:     time.Now().Add(s.refreshExpiry),
		CreatedAt:     time.Now(),
		IsRevoked:     false,
	}

	if err := s.tokenRepo.SaveRefreshToken(ctx, refreshTokenModel); err != nil {
		return nil, err
	}

	// Cache the access token for quick validation
	if err := s.cacheRepo.Set(ctx, CacheKeyAccessToken+accessTokenID, accessTokenModel, s.accessExpiry); err != nil {
		// Not critical, continue
	}

	return &TokenCreateResponse{
		AccessToken:  accessToken,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    int(s.accessExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

// RefreshTokens exchanges a valid refresh token for a new access token and refresh token pair.
// It validates the refresh token, checks scope restrictions, and revokes the old tokens
// before generating new ones.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken, clientID, requestedScope string) (*TokenCreateResponse, error) {
	// Hash the refresh token
	tokenHash, err := hash.HashPassword(refreshToken)
	if err != nil {
		return nil, errors.Internal(errors.ErrMsgFailedToHashRefreshToken)
	}

	// Find the refresh token
	token, err := s.tokenRepo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.Unauthorized(errors.ErrMsgInvalidToken)
	}

	// Validate token
	if token.IsRevoked {
		return nil, errors.Unauthorized(errors.ErrMsgTokenRevoked)
	}
	if time.Now().After(token.ExpiresAt) {
		return nil, errors.Unauthorized(errors.ErrMsgTokenExpired)
	}
	if token.ClientID != clientID {
		return nil, errors.Unauthorized("refresh token was not issued to this client")
	}

	// Validate requested scope
	scope := token.Scope
	if requestedScope != "" {
		if !s.isScopeSubset(requestedScope, token.Scope) {
			return nil, errors.BadRequest("requested scope exceeds original scope")
		}
		scope = requestedScope
	}

	// Revoke old tokens
	if err := s.tokenRepo.RevokeRefreshToken(ctx, token.TokenID); err != nil {
		return nil, err
	}
	if token.AccessTokenID != "" {
		if err := s.tokenRepo.RevokeAccessToken(ctx, token.AccessTokenID); err != nil {
			// Not critical, continue
		}
	}

	// Create new tokens
	return s.CreateTokens(ctx, token.UserID, token.ClientID, scope, "")
}

// RevokeAccessToken invalidates an access token if it belongs to the specified client.
// It removes the token from the cache and marks it as revoked in the database.
func (s *Service) RevokeAccessToken(ctx context.Context, tokenValue, clientID string) error {
	// Parse JWT to get token ID
	tokenID, err := s.getTokenIDFromJWT(tokenValue)
	if err != nil {
		return err
	}

	// Verify token belongs to client
	token, err := s.tokenRepo.FindAccessToken(ctx, tokenID)
	if err != nil || token == nil {
		return errors.NotFound(errors.ErrMsgTokenNotFound)
	}

	if token.ClientID != clientID {
		return errors.Forbidden("token does not belong to client")
	}

	// Revoke token
	if err := s.tokenRepo.RevokeAccessToken(ctx, tokenID); err != nil {
		return err
	}

	// Remove from cache
	s.cacheRepo.Delete(ctx, CacheKeyAccessToken+tokenID)

	return nil
}

// RevokeRefreshToken invalidates a refresh token and its associated access token
// if they belong to the specified client.
func (s *Service) RevokeRefreshToken(ctx context.Context, tokenValue, clientID string) error {
	// Hash the refresh token
	tokenHash, err := hash.HashPassword(tokenValue)
	if err != nil {
		return errors.Internal(errors.ErrMsgFailedToHashRefreshToken)
	}

	// Find the refresh token
	token, err := s.tokenRepo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil || token == nil {
		return errors.NotFound(errors.ErrMsgTokenNotFound)
	}

	if token.ClientID != clientID {
		return errors.Forbidden("token does not belong to client")
	}

	// Revoke refresh token and associated access token
	if err := s.tokenRepo.RevokeRefreshToken(ctx, token.TokenID); err != nil {
		return err
	}

	if token.AccessTokenID != "" {
		s.tokenRepo.RevokeAccessToken(ctx, token.AccessTokenID)
		s.cacheRepo.Delete(ctx, CacheKeyAccessToken+token.AccessTokenID)
	}

	return nil
}

// ValidateAccessToken verifies the signature and validity of an access token.
// It checks if the token has been revoked and returns the claims if the token is valid.
func (s *Service) ValidateAccessToken(ctx context.Context, tokenValue string) (*jwt.MapClaims, error) {
	// Use the jwtutil.ValidateTokenForRevocation function to validate the token format
	// and extract the token ID
	tokenID, err := jwtutil.ValidateTokenForRevocation(tokenValue)
	if err != nil {
		return nil, err
	}

	// Parse the token to get claims for additional checks and return value
	token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})

	if err != nil {
		return nil, errors.Unauthorized(errors.ErrMsgInvalidToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.Unauthorized(errors.ErrMsgInvalidTokenClaims)
	}

	// Check cache first
	if cached, err := s.cacheRepo.Get(ctx, CacheKeyAccessToken+tokenID); err == nil && cached != "" {
		// Token found in cache, check if revoked
		// This would need proper deserialization
	}

	// Check database
	isRevoked, err := s.tokenRepo.IsAccessTokenRevoked(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	if isRevoked {
		return nil, errors.Unauthorized(errors.ErrMsgTokenRevoked)
	}

	return &claims, nil
}

// ListTokens retrieves a paginated list of access tokens for a specific user.
func (s *Service) ListTokens(ctx context.Context, userID uint, page, limit int) (*TokenListResponse, error) {
	accessTokens, totalAccess, err := s.tokenRepo.FindAccessTokensByUserID(ctx, userID, page, limit)
	if err != nil {
		return nil, err
	}

	var tokens []TokenInfo
	for _, token := range accessTokens {
		tokens = append(tokens, TokenInfo{
			ID:        token.TokenID,
			ClientID:  token.ClientID,
			UserID:    token.UserID,
			Scope:     token.Scope,
			ExpiresAt: token.ExpiresAt,
			CreatedAt: token.CreatedAt,
			IsRevoked: token.IsRevoked,
		})
	}

	return &TokenListResponse{
		Tokens:  tokens,
		Total:   totalAccess,
		Page:    page,
		PerPage: limit,
	}, nil
}

// RevokeToken invalidates an access token if it belongs to the specified user.
func (s *Service) RevokeToken(ctx context.Context, tokenID string, userID uint) error {
	token, err := s.tokenRepo.FindAccessToken(ctx, tokenID)
	if err != nil {
		return err
	}
	if token == nil {
		return errors.NotFound("token not found")
	}

	// Check ownership
	if token.UserID != userID {
		return errors.Forbidden("not authorized to revoke this token")
	}

	return s.tokenRepo.RevokeAccessToken(ctx, tokenID)
}

// RevokeTokensByAuthCode invalidates all access tokens associated with a specific authorization code.
func (s *Service) RevokeTokensByAuthCode(ctx context.Context, authCode string) error {
	return s.tokenRepo.RevokeAccessTokensByAuthCode(ctx, authCode)
}

// createAccessToken generates a new JWT access token with the specified claims.
func (s *Service) createAccessToken(userID uint, clientID, scope string) (string, string, error) {
	tokenID := uuid.New().String()
	now := time.Now()

	claims := jwt.MapClaims{
		jwtutil.ClaimKeyJTI:   tokenID,
		jwtutil.ClaimKeySub:   userID,
		jwtutil.ClaimKeyAud:   clientID,
		jwtutil.ClaimKeyScope: scope,
		jwtutil.ClaimKeyIAT:   now.Unix(),
		jwtutil.ClaimKeyEXP:   now.Add(s.accessExpiry).Unix(),
		jwtutil.ClaimKeyISS:   jwtutil.TokenIssuer,
		jwtutil.ClaimKeyType:  jwtutil.TokenTypeAccess,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", err
	}

	return signedToken, tokenID, nil
}

// createRefreshToken generates a new secure random refresh token.
func (s *Service) createRefreshToken() (string, string, error) {
	tokenID := uuid.New().String()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(b)
	return refreshToken, tokenID, nil
}

// getTokenIDFromJWT extracts the token ID (jti) claim from a JWT without validating the signature.
func (s *Service) getTokenIDFromJWT(tokenValue string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenValue, jwt.MapClaims{})
	if err != nil {
		return "", errors.Unauthorized(errors.ErrMsgInvalidTokenFormat)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.Unauthorized(errors.ErrMsgInvalidTokenClaims)
	}

	tokenID, ok := claims[jwtutil.ClaimKeyJTI].(string)
	if !ok {
		return "", errors.Unauthorized(errors.ErrMsgInvalidTokenID)
	}

	return tokenID, nil
}

// isScopeSubset checks if the requested scope is a subset of the existing scope.
func (s *Service) isScopeSubset(requested, existing string) bool {
	requestedScopes := strings.Split(requested, " ")
	existingScopes := strings.Split(existing, " ")

	for _, req := range requestedScopes {
		found := false
		for _, exists := range existingScopes {
			if req == exists {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
