// Package jwt provides utilities for creating and validating JWT tokens
// used throughout the application for authentication and authorization.
package jwt

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/verigate/verigate-server/internal/pkg/config"
)

// Claims represents the custom claims structure for JWT tokens.
// It extends the standard JWT RegisteredClaims with application-specific fields.
type Claims struct {
	UserID               uint `json:"user_id"` // ID of the authenticated user
	jwt.RegisteredClaims      // Standard JWT claims (iss, exp, etc.)
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
			Issuer:    "oauth-server",
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
