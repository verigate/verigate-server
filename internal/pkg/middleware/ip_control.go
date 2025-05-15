// Package middleware provides HTTP middleware functions for the application.
package middleware

import (
	"net"
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

// IPControl holds the IP address whitelist and blacklist configurations.
// It provides a way to control access to the API based on client IP addresses.
type IPControl struct {
	Whitelist []string // List of allowed IP addresses or CIDR ranges
	Blacklist []string // List of blocked IP addresses or CIDR ranges
}

// NewIPControl creates a new IP control configuration with whitelist and blacklist.
// Both parameters accept IP addresses or CIDR notation (e.g., "192.168.1.0/24").
func NewIPControl(whitelist, blacklist []string) *IPControl {
	return &IPControl{
		Whitelist: whitelist,
		Blacklist: blacklist,
	}
}

// IPControlMiddleware creates a middleware that controls access based on client IP address.
// The middleware first checks if the client IP is blacklisted, then checks if it's whitelisted.
// If a whitelist is provided and the client IP is not in it, access is denied.
// If the client IP is blacklisted, access is denied regardless of whitelist.
func IPControlMiddleware(ipControl *IPControl) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Check blacklist first
		for _, blockedIP := range ipControl.Blacklist {
			if matchIP(clientIP, blockedIP) {
				c.Error(errors.Forbidden("Access denied from your IP address"))
				c.Abort()
				return
			}
		}

		// If whitelist is not empty, check if IP is in whitelist
		if len(ipControl.Whitelist) > 0 {
			allowed := false
			for _, allowedIP := range ipControl.Whitelist {
				if matchIP(clientIP, allowedIP) {
					allowed = true
					break
				}
			}

			if !allowed {
				c.Error(errors.Forbidden("Your IP address is not authorized"))
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// matchIP checks if an IP address matches a pattern.
// It supports both direct IP comparison and CIDR notation (e.g., 192.168.1.0/24).
// Returns true if the IP matches the pattern, false otherwise.
func matchIP(ip, pattern string) bool {
	// Direct IP comparison
	if !strings.Contains(pattern, "/") {
		return ip == pattern
	}

	// CIDR pattern matching
	_, ipNet, err := net.ParseCIDR(pattern)
	if err != nil {
		return false
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	return ipNet.Contains(ipAddr)
}
