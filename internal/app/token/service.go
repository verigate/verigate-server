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
)

type CacheRepository interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type Service struct {
	tokenRepo     Repository
	cacheRepo     CacheRepository
	authService   *auth.Service
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

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
		return nil, errors.Internal("failed to hash access token")
	}

	refreshTokenHash, err := hash.HashPassword(refreshToken)
	if err != nil {
		return nil, errors.Internal("failed to hash refresh token")
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
	if err := s.cacheRepo.Set(ctx, "access_token:"+accessTokenID, accessTokenModel, s.accessExpiry); err != nil {
		// Not critical, continue
	}

	return &TokenCreateResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.accessExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func (s *Service) RefreshTokens(ctx context.Context, refreshToken, clientID, requestedScope string) (*TokenCreateResponse, error) {
	// Hash the refresh token
	tokenHash, err := hash.HashPassword(refreshToken)
	if err != nil {
		return nil, errors.Internal("failed to hash refresh token")
	}

	// Find the refresh token
	token, err := s.tokenRepo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.Unauthorized("invalid refresh token")
	}

	// Validate token
	if token.IsRevoked {
		return nil, errors.Unauthorized("refresh token has been revoked")
	}
	if time.Now().After(token.ExpiresAt) {
		return nil, errors.Unauthorized("refresh token has expired")
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

func (s *Service) RevokeAccessToken(ctx context.Context, tokenValue, clientID string) error {
	// Parse JWT to get token ID
	tokenID, err := s.getTokenIDFromJWT(tokenValue)
	if err != nil {
		return err
	}

	// Verify token belongs to client
	token, err := s.tokenRepo.FindAccessToken(ctx, tokenID)
	if err != nil || token == nil {
		return errors.NotFound("token not found")
	}

	if token.ClientID != clientID {
		return errors.Forbidden("token does not belong to client")
	}

	// Revoke token
	if err := s.tokenRepo.RevokeAccessToken(ctx, tokenID); err != nil {
		return err
	}

	// Remove from cache
	s.cacheRepo.Delete(ctx, "access_token:"+tokenID)

	return nil
}

func (s *Service) RevokeRefreshToken(ctx context.Context, tokenValue, clientID string) error {
	// Hash the refresh token
	tokenHash, err := hash.HashPassword(tokenValue)
	if err != nil {
		return errors.Internal("failed to hash refresh token")
	}

	// Find the refresh token
	token, err := s.tokenRepo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil || token == nil {
		return errors.NotFound("token not found")
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
		s.cacheRepo.Delete(ctx, "access_token:"+token.AccessTokenID)
	}

	return nil
}

func (s *Service) ValidateAccessToken(ctx context.Context, tokenValue string) (*jwt.MapClaims, error) {
	// Parse and validate JWT
	token, err := jwt.Parse(tokenValue, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Unauthorized("unexpected signing method")
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, errors.Unauthorized("invalid token")
	}

	if !token.Valid {
		return nil, errors.Unauthorized("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.Unauthorized("invalid token claims")
	}

	// Check if token is revoked
	tokenID, ok := claims["jti"].(string)
	if !ok {
		return nil, errors.Unauthorized("invalid token ID")
	}

	// Check cache first
	if cached, err := s.cacheRepo.Get(ctx, "access_token:"+tokenID); err == nil && cached != "" {
		// Token found in cache, check if revoked
		// This would need proper deserialization
	}

	// Check database
	isRevoked, err := s.tokenRepo.IsAccessTokenRevoked(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	if isRevoked {
		return nil, errors.Unauthorized("token has been revoked")
	}

	return &claims, nil
}

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

func (s *Service) RevokeTokensByAuthCode(ctx context.Context, authCode string) error {
	return s.tokenRepo.RevokeAccessTokensByAuthCode(ctx, authCode)
}

// Helper methods

func (s *Service) createAccessToken(userID uint, clientID, scope string) (string, string, error) {
	tokenID := uuid.New().String()
	now := time.Now()

	claims := jwt.MapClaims{
		"jti":   tokenID,
		"sub":   userID,
		"aud":   clientID,
		"scope": scope,
		"iat":   now.Unix(),
		"exp":   now.Add(s.accessExpiry).Unix(),
		"iss":   "oauth-server",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", err
	}

	return signedToken, tokenID, nil
}

func (s *Service) createRefreshToken() (string, string, error) {
	tokenID := uuid.New().String()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(b)
	return refreshToken, tokenID, nil
}

func (s *Service) getTokenIDFromJWT(tokenValue string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenValue, jwt.MapClaims{})
	if err != nil {
		return "", errors.Unauthorized("invalid token format")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.Unauthorized("invalid token claims")
	}

	tokenID, ok := claims["jti"].(string)
	if !ok {
		return "", errors.Unauthorized("invalid token ID")
	}

	return tokenID, nil
}

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
