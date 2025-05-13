package pkce

import (
	"crypto/sha256"
	"encoding/base64"
)

func VerifyCodeChallenge(codeVerifier, codeChallenge, method string) bool {
	if method == "plain" {
		return codeVerifier == codeChallenge
	}

	if method == "S256" {
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		return challenge == codeChallenge
	}

	return false
}
