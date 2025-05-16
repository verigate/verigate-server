// Package auth provides authentication and authorization services
// for the application, including token generation, validation,
// and management of authentication sessions.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/verigate/verigate-server/internal/pkg/config"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
	"github.com/verigate/verigate-server/internal/pkg/utils/hash"
	jwtutil "github.com/verigate/verigate-server/internal/pkg/utils/jwt"
)

// Service handles authentication-related business logic.
// It manages the creation, validation, and revocation of tokens,
// as well as other authentication-related operations.
type Service struct {
	repo              Repository
	privateKey        *rsa.PrivateKey
	publicKey         *rsa.PublicKey
	accessExpiry      time.Duration
	refreshExpiry     time.Duration
	accessTokenIssuer string
}

// NewService creates a new authentication service instance.
// It initializes the service with RSA keys and token expiration settings
// loaded from the application configuration.
func NewService(repo Repository) *Service {
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
		repo:              repo,
		privateKey:        privateKey,
		publicKey:         publicKey,
		accessExpiry:      accessExpiry,
		refreshExpiry:     refreshExpiry,
		accessTokenIssuer: "verigate-web", // Distinct from OAuth tokens
	}
}

// CreateTokenPair generates an access token and refresh token pair for a user.
// The access token is a JWT with user identity claims, and the refresh token
// is a secure random string that can be exchanged for a new token pair.
// User agent and IP address are stored for audit purposes.
func (s *Service) CreateTokenPair(ctx context.Context, userID uint, userAgent, ipAddress string) (*TokenPair, error) {
	// Generate access token
	tokenID := uuid.New().String()
	now := time.Now()
	accessExpiry := now.Add(s.accessExpiry)

	claims := jwt.MapClaims{
		"jti":  tokenID,
		"sub":  userID,
		"iat":  now.Unix(),
		"exp":  accessExpiry.Unix(),
		"iss":  s.accessTokenIssuer,
		"type": jwtutil.TokenTypeAccess,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, errors.Internal("failed to generate access token")
	}

	// Generate refresh token
	refreshTokenID := uuid.New().String()
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return nil, errors.Internal("failed to generate refresh token")
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)
	refreshExpiry := now.Add(s.refreshExpiry)

	// Hash the refresh token
	hashedRefreshToken, err := hash.HashPassword(refreshToken)
	if err != nil {
		return nil, errors.Internal("failed to hash refresh token")
	}

	// Store the refresh token
	refreshTokenModel := &RefreshToken{
		ID:        refreshTokenID,
		UserID:    userID,
		Token:     hashedRefreshToken,
		ExpiresAt: refreshExpiry,
		CreatedAt: now,
		IsRevoked: false,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	if err := s.repo.SaveRefreshToken(ctx, refreshTokenModel); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExpiry,
		RefreshTokenExpiresAt: refreshExpiry,
	}, nil
}

// RefreshTokens uses a refresh token to issue a new token pair (Refresh Token Rotation pattern).
// It validates the provided refresh token, revokes it, and generates a new token pair.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken, userAgent, ipAddress string) (*TokenPair, error) {
	// Find the refresh token
	token, err := s.repo.FindRefreshTokenByToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if token == nil {
		return nil, errors.Unauthorized("invalid refresh token")
	}

	// Validate token
	if token.IsRevoked {
		// If token is revoked, revoke all user tokens for security
		s.repo.RevokeAllUserRefreshTokens(ctx, token.UserID)
		return nil, errors.Unauthorized("refresh token has been revoked")
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, errors.Unauthorized("refresh token has expired")
	}

	// Revoke current refresh token (RTR pattern)
	if err := s.repo.RevokeRefreshToken(ctx, token.ID); err != nil {
		return nil, err
	}

	// Create new token pair
	return s.CreateTokenPair(ctx, token.UserID, userAgent, ipAddress)
}

// ValidateAccessToken validates an access token and returns the user ID.
// It checks the token's signature, expiration, issuer, and type.
func (s *Service) ValidateAccessToken(tokenString string) (uint, error) {
	// Use the common JWT utility for consistent token validation
	return jwtutil.ValidateAccessTokenWithClaims(tokenString, s.accessTokenIssuer)
}

// RevokeRefreshToken revokes a specific refresh token.
// It marks the token as revoked in the repository.
func (s *Service) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	return s.repo.RevokeRefreshToken(ctx, tokenID)
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
// It marks all tokens associated with the user as revoked in the repository.
func (s *Service) RevokeAllUserRefreshTokens(ctx context.Context, userID uint) error {
	return s.repo.RevokeAllUserRefreshTokens(ctx, userID)
}
