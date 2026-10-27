package middleware

import (
	"net/http"
	"time"

	apiMiddleware "github.com/LandcLi/landc-go/api/middleware/gin"
	"github.com/LandcLi/landc-go/log/facade"

	authApi "github.com/LandcLi/LandcSSO/api/auth"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/gin-gonic/gin"
)

// CtxEnricherMiddleware extracts request info and stores in context for Handler to use.
// 同时写入 gin context 与 request context（landc-go frame v0.8.1 向 handler 传入
// c.Request.Context()，controller 通过 ctx.Value 读取这些值）。
func CtxEnricherMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
		userAgent := c.GetHeader("User-Agent")

		// gin.Context 侧：供直接用 gin API 的 handler
		c.Set("IP", ip)
		c.Set("DeviceFingerprint", deviceFingerprint)
		c.Set("UserAgent", userAgent)

		// context.Context 侧：委托给 api/auth.RequestInfoEnricher，
		// 保证键类型只有一个定义（自定义类型，避免 SA1029 的字符串键冲突）。
		c.Request = c.Request.WithContext(authApi.RequestInfoEnricher(c.Request.Context(), c))

		c.Next()
	}
}

// Cors 跨域中间件（基于配置的 Origin 白名单，默认拒绝跨域）
func Cors() gin.HandlerFunc {
	allowOrigins := make(map[string]bool)
	for _, origin := range config.GetConfig().AllowedOrigins() {
		allowOrigins[origin] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && allowOrigins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == "OPTIONS" {
			// 未在白名单内的预检请求直接拒绝
			if origin == "" || !allowOrigins[origin] {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.AbortWithStatus(http.StatusNoContent)
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
		//
		// trace_id 由 createHandler（或 trace 中间件）写入 gin.Context，
		// c.Next() 之后就能读到。带上它，同一请求的日志才能和下游服务串起来。
		traceID := c.GetString("trace_id")
		if traceID == "" {
			traceID = c.GetHeader("X-Trace-ID")
		}
		facade.Infof("| %3d | %13v | %15s | %s | %s | trace=%s",
			statusCode,
			latency,
			clientIP,
			method,
			path,
			traceID,
		)
	}
}
