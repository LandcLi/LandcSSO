package serverlib

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/LandcLi/landc-go/frame/pkg/web"
	"github.com/LandcLi/landc-go/tools/ratelimit"
	"github.com/gin-gonic/gin"

	lumserverlib "github.com/LandcLi/LandcUserManager/serverlib"

	"github.com/LandcLi/LandcSSO/api"
	"github.com/LandcLi/LandcSSO/internal/middleware"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	userapi "github.com/LandcLi/LandcUserManager/api/user"

	// 触发默认实现注册链（DAO / Service / Controller），
	// 保证任何通过 serverlib 装配的宿主都能解析到实现，无需额外 import。
	_ "github.com/LandcLi/LandcSSO/internal"
)

// options 为装配配置。
type options struct {
	authEnabled    bool
	rateLimit      bool
	configPath     string
	userManagerMode string
	userManagerURL  string

	// loginRateLimiter 登录/令牌接口限流（每 IP 每秒 5 次，突发 10 次）
	loginRateLimiter *ratelimit.TokenBucket
}

// Option 为装配配置项。
type Option func(*options)

// WithAuth 是否挂载全局鉴权中间件（公开路径白名单放行），默认 true。
func WithAuth(enabled bool) Option {
	return func(o *options) { o.authEnabled = enabled }
}

// WithRateLimit 是否对 /auth/login、/auth/token、/auth/refresh-token 限流，默认 true。
func WithRateLimit(enabled bool) Option {
	return func(o *options) { o.rateLimit = enabled }
}

// WithConfigPath 指定配置文件路径（默认 config.yaml，找不到时会向上级目录搜索）。
func WithConfigPath(path string) Option {
	return func(o *options) { o.configPath = path }
}

// WithUserManager 覆盖用户中心接入方式，优先级高于配置文件。
// mode: local（进程内）| remote（HTTP）。
func WithUserManager(mode, baseURL string) Option {
	return func(o *options) {
		o.userManagerMode = mode
		o.userManagerURL = baseURL
	}
}

// RegisterToRouter 装配 LandcSSO 的默认实现并注册到 server。
//
// 只装配、不接管：不创建 engine、不调用 Run，调用方可继续追加自有路由。
// 除框架 bootstrap（配置/DB/缓存/JWT）外，本函数自会：
//   - 加载 SSO 自有配置（若尚未加载）
//   - 建表（受 database.auto_migrate 控制）与种子数据（受 seed.enabled 控制）
//   - 按 user_manager.mode 接入用户中心：local 走进程内，remote 走 HTTP
//   - 挂载 CORS / 上下文增强 / 请求日志 / 鉴权 / 登录限流中间件
//   - 注册 /auth/* 与 /client/* 路由
func RegisterToRouter(s *web.Server, opts ...Option) error {
	o := &options{
		authEnabled:      true,
		rateLimit:        true,
		configPath:       "config.yaml",
		loginRateLimiter: ratelimit.NewTokenBucket(5, 10),
	}
	for _, opt := range opts {
		opt(o)
	}

	// SSO 自有配置（保留 legacy 单一入口语义，幂等）
	if err := config.Init(o.configPath); err != nil {
		return fmt.Errorf("serverlib: load config: %w", err)
	}
	cfg := config.GetConfig()
	if cfg == nil {
		return fmt.Errorf("serverlib: config not initialized")
	}

	if err := EnsureSchema(); err != nil {
		return err
	}
	if err := Seed(); err != nil {
		return err
	}

	// 用户中心接入
	mode := cfg.UserManager.Mode
	baseURL := cfg.UserManager.BaseURL
	if o.userManagerMode != "" {
		mode = o.userManagerMode
	}
	if o.userManagerURL != "" {
		baseURL = o.userManagerURL
	}
	if err := wireUserManager(mode, baseURL); err != nil {
		return err
	}

	// 第三方登录适配器（未配置 third_party 时为 no-op）
	if len(cfg.ThirdParty) > 0 {
		if err := service.InitWithConfig(&service.ThirdPartyGlobalConfig{
			ThirdParty: cfg.ThirdParty,
		}); err != nil {
			return fmt.Errorf("serverlib: init third party adapters: %w", err)
		}
	}

	engine := s.Engine()
	engine.Use(middleware.Cors())
	engine.Use(middleware.CtxEnricherMiddleware())
	engine.Use(middleware.RequestLogger())

	if o.rateLimit {
		engine.Use(loginRateLimitMiddleware(o.loginRateLimiter))
	}
	if o.authEnabled {
		engine.Use(middleware.AuthRequired())
	}

	return api.RegisterDefaultRoutes(s)
}

// wireUserManager 按模式装配用户中心：
//   - local：进程内注册 LUM 实现，SSO 通过 UserGateway 直接调用，无 HTTP 跳转；
//   - remote：注册 HTTP 代理，SSO 通过 UserGateway 调用远端 LUM。
func wireUserManager(mode, baseURL string) error {
	switch mode {
	case "", config.UserManagerModeLocal:
		// 只装实现、不挂 LUM 的路由与中间件，避免污染 SSO 的 URL 空间与中间件链
		if err := lumserverlib.Install(); err != nil {
			return fmt.Errorf("serverlib: install in-process user manager: %w", err)
		}
		return nil
	case config.UserManagerModeRemote:
		if baseURL == "" {
			return fmt.Errorf("serverlib: user_manager.baseUrl is required in remote mode")
		}
		userapi.UserGateway.ProvideRemote(baseURL)
		return nil
	default:
		return fmt.Errorf("serverlib: unknown user_manager.mode %q (want %q or %q)",
			mode, config.UserManagerModeLocal, config.UserManagerModeRemote)
	}
}

// loginRateLimitMiddleware 对登录与令牌端点限流，其余路径直接放行。
func loginRateLimitMiddleware(limiter *ratelimit.TokenBucket) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if !strings.Contains(path, "/auth/login") &&
			!strings.Contains(path, "/auth/token") &&
			!strings.Contains(path, "/auth/refresh-token") {
			c.Next()
			return
		}
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    42900,
				"message": "too many requests, please try again later",
			})
			return
		}
		c.Next()
	}
}
