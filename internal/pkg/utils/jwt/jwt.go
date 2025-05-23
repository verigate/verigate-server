// Package jwt provides utilities for creating and validating JWT tokens
// used throughout the application for authentication and authorization.
package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/verigate/verigate-server/internal/pkg/config"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

// Token type constants
const (
	TokenTypeAccess  = "access"       // Access tokens used for API authorization
	TokenTypeRefresh = "refresh"      // Refresh tokens used to obtain new access tokens
	TokenIssuer      = "oauth-server" // Issuer value for all JWT tokens

	// JWT claim key constants
	ClaimKeyJTI    = "jti"     // JWT ID claim
	ClaimKeySub    = "sub"     // Subject claim (user ID)
	ClaimKeyAud    = "aud"     // Audience claim (client ID)
	ClaimKeyScope  = "scope"   // Scope claim
	ClaimKeyIAT    = "iat"     // Issued At claim
	ClaimKeyEXP    = "exp"     // Expiration claim
	ClaimKeyISS    = "iss"     // Issuer claim
	ClaimKeyType   = "type"    // Token type claim
	ClaimKeyUserID = "user_id" // Custom user ID claim
)

// Claims represents the custom claims structure for JWT tokens.
// It extends the standard JWT RegisteredClaims with application-specific fields.
type Claims struct {
	UserID               uint   `json:"user_id"`        // ID of the authenticated user
	TokenType            string `json:"type,omitempty"` // Type of token (access or refresh)
	jwt.RegisteredClaims        // Standard JWT claims (iss, exp, etc.)
}

var (
	privateKey *rsa.PrivateKey // RSA private key for token signing
	publicKey  *rsa.PublicKey  // RSA public key for token validation
)

// InitKeys initializes the JWT package by loading the RSA keys from configuration.
// Returns an error if the keys cannot be parsed or are not provided.
func InitKeys() error {
	// Validate that keys are provided
	if config.AppConfig.JWTPrivateKey == "" {
		return fmt.Errorf("JWT_PRIVATE_KEY environment variable is not set")
	}

	if config.AppConfig.JWTPublicKey == "" {
		return fmt.Errorf("JWT_PUBLIC_KEY environment variable is not set")
	}

	// Parse the private key
	pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.AppConfig.JWTPrivateKey))
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	privateKey = pk

	// Parse the public key
	pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(config.AppConfig.JWTPublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey = pub

	return nil
}

// GenerateToken creates a new JWT token for the specified user.
// It sets standard claims including expiration time based on configuration.
// Returns the signed token string or an error if signing fails.
func GenerateToken(userID uint) (string, error) {
	expiry, err := time.ParseDuration(config.AppConfig.JWTAccessExpiry)
	if err != nil {
		return "", err
	}

	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    TokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// GenerateCustomToken creates a JWT token with custom parameters.
// It allows specifying the issuer, token type, and expiration duration.
// Returns the signed token string or an error if signing fails.
func GenerateCustomToken(userID uint, issuer string, tokenType string, tokenID string, expiry time.Duration) (string, error) {
	// Verify that the private key is available
	if privateKey == nil {
		return "", fmt.Errorf("JWT private key not initialized")
	}

	now := time.Now()

	claims := jwt.MapClaims{
		ClaimKeyJTI:    tokenID,
		ClaimKeySub:    userID,
		ClaimKeyIAT:    now.Unix(),
		ClaimKeyEXP:    now.Add(expiry).Unix(),
		ClaimKeyISS:    issuer,
		ClaimKeyType:   tokenType,
		ClaimKeyUserID: userID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ValidateToken validates a JWT token and returns the claims if valid.
// This function verifies the token signature, expiration, and other standard validations.
// Returns the parsed claims or an error if validation fails.
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}

// ValidateCustomToken validates a JWT token used for web app authentication.
// This function is distinct from ValidateToken which is used for OAuth.
// It additionally verifies the token issuer matches the expected value.
// Returns the parsed claims or an error if validation fails.
func ValidateCustomToken(tokenString string, issuer string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Verify issuer
		if claims.RegisteredClaims.Issuer != issuer {
			return nil, jwt.NewValidationError("invalid issuer", jwt.ValidationErrorIssuer)
		}
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

// ValidateAccessTokenWithClaims validates an access token and verifies specific claims.
// It checks the token's signature, expiration, type, and issuer.
// This function is a more comprehensive validation suitable for access tokens.
// Returns the user ID from the token or a detailed error if validation fails.
func ValidateAccessTokenWithClaims(tokenString string, expectedIssuer string) (uint, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return 0, errors.Unauthorized(errors.ErrMsgInvalidToken + ": " + err.Error())
	}

	if !token.Valid {
		return 0, errors.Unauthorized(errors.ErrMsgInvalidToken)
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.Unauthorized(errors.ErrMsgInvalidTokenClaims)
	}

	// Check token type
	tokenType, ok := claims[ClaimKeyType].(string)
	if !ok || tokenType != TokenTypeAccess {
		return 0, errors.Unauthorized(errors.ErrMsgInvalidTokenType)
	}

	// Check issuer
	issuer, ok := claims[ClaimKeyISS].(string)
	if !ok || issuer != expectedIssuer {
		return 0, errors.Unauthorized(errors.ErrMsgInvalidTokenIssuer)
	}

	// Extract user ID
	userIDFloat, ok := claims[ClaimKeyUserID].(float64)
	if !ok {
		return 0, errors.Unauthorized(errors.ErrMsgInvalidUserID)
	}

	return uint(userIDFloat), nil
}

// ValidateTokenForRevocation validates a token's format and extracts the token ID (jti).
// This function is used when checking if a token has been revoked.
// Returns the token ID from the token or an error if basic validation fails.
func ValidateTokenForRevocation(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Unauthorized(errors.ErrMsgInvalidTokenFormat)
		}
		return publicKey, nil
	})

	if err != nil {
		return "", errors.Unauthorized(errors.ErrMsgInvalidToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.Unauthorized(errors.ErrMsgInvalidTokenClaims)
	}

	// Check if token is revoked
	tokenID, ok := claims[ClaimKeyJTI].(string)
	if !ok {
		return "", errors.Unauthorized(errors.ErrMsgInvalidTokenID)
	}

	return tokenID, nil
}
