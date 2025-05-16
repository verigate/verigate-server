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

// init initializes the JWT package by loading the RSA keys from configuration.
// Panics if the keys cannot be parsed, as this indicates a critical configuration error.
func init() {
	// Initialize keys when config is loaded
	if config.AppConfig.JWTPrivateKey != "" {
		pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.AppConfig.JWTPrivateKey))
		if err != nil {
			panic("failed to parse private key: " + err.Error())
		}
		privateKey = pk
	}

	if config.AppConfig.JWTPublicKey != "" {
		pk, err := jwt.ParseRSAPublicKeyFromPEM([]byte(config.AppConfig.JWTPublicKey))
		if err != nil {
			panic("failed to parse public key: " + err.Error())
		}
		publicKey = pk
	}
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
		return 0, errors.Unauthorized("invalid token: " + err.Error())
	}

	if !token.Valid {
		return 0, errors.Unauthorized("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.Unauthorized("invalid token claims")
	}

	// Check token type
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != TokenTypeAccess {
		return 0, errors.Unauthorized("invalid token type")
	}

	// Check issuer
	issuer, ok := claims["iss"].(string)
	if !ok || issuer != expectedIssuer {
		return 0, errors.Unauthorized("invalid token issuer")
	}

	// Extract user ID
	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		return 0, errors.Unauthorized("invalid user ID in token")
	}

	return uint(userIDFloat), nil
}

// ValidateTokenForRevocation validates a token's format and extracts the token ID (jti).
// This function is used when checking if a token has been revoked.
// Returns the token ID from the token or an error if basic validation fails.
func ValidateTokenForRevocation(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.Unauthorized("unexpected signing method")
		}
		return publicKey, nil
	})

	if err != nil {
		return "", errors.Unauthorized("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.Unauthorized("invalid token claims")
	}

	// Check if token is revoked
	tokenID, ok := claims["jti"].(string)
	if !ok {
		return "", errors.Unauthorized("invalid token ID")
	}

	return tokenID, nil
}
