package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/LandcLi/LandcSSO/api"
	"github.com/LandcLi/LandcSSO/internal/middleware"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/landc-go/frame/pkg/cmd"
	"github.com/LandcLi/landc-go/frame/pkg/web"
	"github.com/LandcLi/landc-go/tools/ratelimit"
	userapi "github.com/LandcLi/LandcUserManager/api/user"
	"github.com/gin-gonic/gin"
)

// loginRateLimiter 登录接口限流（每 IP 每秒 5 次，突发 10 次）
var loginRateLimiter = ratelimit.NewTokenBucket(5, 10)

// Main is the main application command.
var Main = cmd.NewCommand("main", "start HTTP server", func(ctx context.Context, parser *cmd.Parser) error {
	server := web.New()

	// 登录/Token 接口限流（基于路径匹配）
	server.Engine().Use(func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.Contains(path, "/auth/login") ||
			strings.Contains(path, "/auth/token") ||
			strings.Contains(path, "/auth/refresh-token") {
			if !loginRateLimiter.Allow() {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"code":    42900,
					"message": "too many requests, please try again later",
				})
				return
			}
		}
		c.Next()
	})

	// Add SSO middleware
	server.Engine().Use(middleware.Cors())
	server.Engine().Use(middleware.CtxEnricherMiddleware())
	server.Engine().Use(middleware.RequestLogger())

	// Auth middleware: public routes skip auth; protected routes require Bearer token
	server.Engine().Use(middleware.AuthRequired())

	// LandcUserManager - remote mode (local dev)
	userapi.UserGateway.ProvideRemote("http://localhost:18081")

	// 初始化第三方登录适配器（从 config 的 third_party 节点创建并注册）
	if cfg := config.GetConfig(); cfg != nil && len(cfg.ThirdParty) > 0 {
		if err := service.InitWithConfig(&service.ThirdPartyGlobalConfig{
			ThirdParty: cfg.ThirdParty,
		}); err != nil {
			return fmt.Errorf("init third party adapters: %w", err)
		}
	}

	// Register SSO routes
	api.RegisterDefaultRoutes(server)

	return server.RunWithContext(ctx)
})

