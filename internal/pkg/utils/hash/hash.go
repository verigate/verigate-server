// Package hash provides password hashing and verification functions.
// It uses bcrypt for secure password management.
package hash

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword generates a secure hash of a password using bcrypt.
// The hash includes a random salt and uses the default cost factor.
// Returns the hash as a string and any error that occurred during hashing.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CompareHashAndPassword verifies if a password matches a hash.
// It compares the provided password with a previously hashed password.
// Returns nil if the password matches, otherwise returns an error.
func CompareHashAndPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
