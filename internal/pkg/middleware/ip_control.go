package middleware

import (
	"net"
	"strings"

	"github.com/verigate/verigate-server/internal/pkg/utils/errors"

	"github.com/gin-gonic/gin"
)

type IPControl struct {
	Whitelist []string
	Blacklist []string
}

func NewIPControl(whitelist, blacklist []string) *IPControl {
	return &IPControl{
		Whitelist: whitelist,
		Blacklist: blacklist,
	}
}

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

// matchIP supports both single IPs and CIDR notation
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
