package jwt

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/verigate/verigate-server/internal/pkg/config"
)

type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

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
