package middleware

import (
	"context"
	"time"

	"github.com/LandcLi/landc-go/log/facade"
	apiMiddleware 	"github.com/LandcLi/landc-go/api/middleware/gin"

	"github.com/gin-gonic/gin"
)

// CtxEnricherMiddleware extracts request info and stores in context for Handler to use.
func CtxEnricherMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		ctx = context.WithValue(ctx, "IP", c.ClientIP())
		ctx = context.WithValue(ctx, "DeviceFingerprint", c.GetHeader("X-Device-Fingerprint"))
		ctx = context.WithValue(ctx, "UserAgent", c.GetHeader("User-Agent"))
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// Cors 跨域中间件
func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// GinMiddleware LandcCommonApi中间件
func GinMiddleware() gin.HandlerFunc {
	return apiMiddleware.GinMiddleware()
}

// RequestLogger 请求日志中间件
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 开始时间
		startTime := time.Now()

		// 处理请求
		c.Next()

		// 结束时间
		endTime := time.Now()
		// 执行时间
		latency := endTime.Sub(startTime)

		// 请求方法
		method := c.Request.Method
		// 请求路由
		path := c.Request.URL.Path
		// 状态码
		statusCode := c.Writer.Status()
		// 客户端IP
		clientIP := c.ClientIP()

		// 日志格式
		facade.Infof("| %3d | %13v | %15s | %s | %s |",
			statusCode,
			latency,
			clientIP,
			method,
			path,
		)
	}
}
