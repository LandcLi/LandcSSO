package api

import (
	"github.com/LandcLi/LandcSSO/middleware"

	"github.com/LandcLi/LandcSSO/api/auth"
	"github.com/LandcLi/LandcSSO/api/client"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册所有路由
func RegisterDefaultRoutes(r *gin.Engine) {
	// 健康检查
	r.GET("/health", HealthCheck)

	// 认证相关路由 - 高优先级，使用单独的路由组
	authGroup := r.Group("/auth")
	authGroup.Use(middleware.RequestLogger()) // 添加请求日志中间件
	{
		authGroup.POST("/authorize", auth.Authorize)
		authGroup.POST("/token", auth.Token)
		authGroup.POST("/logout", auth.Logout)
		authGroup.GET("/jwks", auth.GetJWKS)
		authGroup.POST("/introspect", auth.Introspect)
		authGroup.POST("/refresh-token", auth.RefreshToken)
		authGroup.POST("/revoke-token", auth.RevokeToken)
		authGroup.POST("/exchange-temp-token", auth.ExchangeTempToken)
		authGroup.POST("/generate-auth-code", auth.GenerateAuthorizationCode)
		authGroup.POST("/verify-auth-code", auth.ValidateAuthorizationCode)
		authGroup.POST("/login", auth.Login)
		authGroup.POST("/third-party-login", auth.GetThirdPartyAuthURL)
	}
	// 客户端管理路由
	clientGroup := r.Group("/client")
	clientGroup.Use(middleware.RequestLogger())
	{
		clientGroup.GET("/list", client.ClientList)
		clientGroup.POST("/create", client.ClientCreate)
		clientGroup.PUT("/update", client.ClientUpdate)
		clientGroup.DELETE("/delete", client.ClientDelete)
	}
}

// HealthCheck 健康检查
func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}
