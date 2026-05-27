package api

import (
	"github.com/LandcLi/LandcSSO/api/auth"
	"github.com/LandcLi/LandcSSO/api/client"
	"github.com/gin-gonic/gin"
)

// RegisterDefaultRoutes registers all routes using Gateway auto-generation.
func RegisterDefaultRoutes(r *gin.Engine) {
	// Health check
	r.GET("/health", HealthCheck)

	// Auth routes via Gateway
	auth.AuthGateway.RegisterRoutes(r)

	// Client management routes via Gateway
	client.ClientGateway.RegisterRoutes(r)
}

// HealthCheck health check endpoint
func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}
