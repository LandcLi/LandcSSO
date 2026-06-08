package middleware

import (
	"strings"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/gin-gonic/gin"
)

var publicPrefixes = []string{
	"/auth/login",
	"/auth/token",
	"/auth/refresh-token",
	"/auth/register",
	"/auth/third-party-login",
	"/auth/verify-auth-code",
	"/auth/introspect",
	"/getjwks",
	"/auth/exchange-temp-token",
}

func isPublicPath(path string) bool {
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// AuthRequired validates the Bearer token and injects UserID into gin context.
// Public routes are skipped; protected routes require a valid token.
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth check for public endpoints
		if isPublicPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "未认证"})
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		if tokenString == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "未认证"})
			return
		}

		authService := service.GetAuthService()
		if authService == nil {
			c.AbortWithStatusJSON(500, gin.H{"error": "认证服务未初始化"})
			return
		}

		claims, err := authService.ValidateToken(c.Request.Context(), tokenString, c.ClientIP(), c.GetHeader("X-Device-Fingerprint"))
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "未认证"})
			return
		}

		c.Set("UserID", claims.UserID)
		c.Set("Username", claims.Username)
		c.Set("Email", claims.Email)
		c.Set("Scope", claims.Scope)
		c.Set("ClientID", claims.ClientID)

		c.Next()
	}
}
