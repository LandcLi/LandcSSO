package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/LandcLi/LandcSSO/internal/middleware"
	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/service"

	"github.com/gin-gonic/gin"
)

var authService *service.AuthService
var clientService *service.ClientService
var auditService *service.AuditService
var monitorService *service.MonitorService

// SetAuthService 设置认证服务
func SetAuthService(s *service.AuthService) {
	authService = s
}

// SetClientService 设置客户端服务
func SetClientService(s *service.ClientService) {
	clientService = s
}

// SetAuditService 设置审计服务
func SetAuditService(s *service.AuditService) {
	auditService = s
}

// SetMonitorService 设置监控服务
func SetMonitorService(s *service.MonitorService) {
	monitorService = s
}

// RegisterRoutes 注册所有路由
func RegisterRoutes(r *gin.Engine) {
	// 健康检查
	r.GET("/health", HealthCheck)

	// 认证相关路由 - 高优先级，使用单独的路由组
	authGroup := r.Group("/auth")
	authGroup.Use(middleware.RequestLogger()) // 添加请求日志中间件
	{
		authGroup.GET("/authorize", Authorize)
		authGroup.POST("/token", Token)
		authGroup.POST("/logout", Logout)
		authGroup.GET("/userinfo", UserInfo)
		authGroup.GET("/jwks", JWKS)
		authGroup.POST("/introspect", Introspect)
	}

	// 用户管理路由
	userGroup := r.Group("/user")
	userGroup.Use(middleware.RequestLogger())
	{
		userGroup.POST("/register", Register)
		userGroup.POST("/login", Login)
		userGroup.POST("/send-verify-code", SendVerifyCode)
		userGroup.POST("/verify-code-login", VerifyCodeLogin)
		userGroup.POST("/third-party-login", ThirdPartyLogin)
		userGroup.GET("/profile", GetProfile)
		userGroup.PUT("/profile", UpdateProfile)
		userGroup.POST("/change-password", ChangePassword)
	}

	// 客户端管理路由
	clientGroup := r.Group("/client")
	clientGroup.Use(middleware.RequestLogger())
	{
		clientGroup.GET("/list", GetClientList)
		clientGroup.POST("/create", CreateClient)
		clientGroup.PUT("/update", UpdateClient)
		clientGroup.DELETE("/delete", DeleteClient)
	}

	// 审计日志路由
	auditGroup := r.Group("/audit")
	auditGroup.Use(middleware.RequestLogger())
	{
		auditGroup.GET("/list", GetAuditList)
		auditGroup.GET("/detail/:id", GetAuditDetail)
		auditGroup.GET("/user/:user_id", GetUserAuditList)
		auditGroup.GET("/type/:event_type", GetTypeAuditList)
	}

	// 监控路由
	monitorGroup := r.Group("/monitor")
	monitorGroup.Use(middleware.RequestLogger())
	{
		monitorGroup.GET("/system/status", GetSystemStatus)
		monitorGroup.GET("/auth/metrics", GetAuthMetrics)
		monitorGroup.GET("/token/metrics", GetTokenMetrics)
		monitorGroup.GET("/anomaly/events", GetAnomalyEvents)
	}
}

// HealthCheck 健康检查
func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}

// Authorize 授权端点
func Authorize(c *gin.Context) {
	// 获取请求参数
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	// 验证必要参数
	if clientID == "" || redirectURI == "" || responseType == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// 验证response_type
	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "Only code response type is supported",
		})
		return
	}

	// 验证客户端
	if clientService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Service not initialized",
		})
		return
	}

	client, err := clientService.GetByClientID(clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Client not found",
		})
		return
	}

	// 验证客户端状态
	if client.Status != 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client is disabled",
		})
		return
	}

	// 验证redirect_uri是否在客户端配置的redirect_uris中
	// TODO: 实现redirect_uri验证逻辑

	// 检查用户是否已登录（暂时使用模拟登录状态）
	// TODO: 实现真实的用户登录状态检查
	userID := uint(1) // 模拟已登录用户ID

	// 检查authService是否初始化
	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Service not initialized",
		})
		return
	}

	// 生成授权码
	authorizationCode, err := authService.GenerateAuthorizationCode(userID, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate authorization code",
		})
		return
	}

	// 重定向到redirect_uri，携带授权码和state参数
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authorizationCode, state)
	c.Redirect(http.StatusFound, redirectURL)
}

// Token 令牌端点
func Token(c *gin.Context) {
	var req struct {
		GrantType    string `json:"grant_type" binding:"required"`
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri"`
		RefreshToken string `json:"refresh_token"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		Scope        string `json:"scope"`
		CodeVerifier string `json:"code_verifier"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 处理不同的授权类型
	switch req.GrantType {
	case "refresh_token":
		// 处理刷新令牌
		// 获取IP地址和设备指纹
		ip := c.ClientIP()
		deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

		resp, err := authService.RefreshToken(req.RefreshToken, ip, deviceFingerprint)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, resp)
	case "password":
		// 处理密码授权
		loginReq := &model.UserLoginRequest{
			Username: req.Username,
			Password: req.Password,
		}
		// 获取IP地址、设备指纹和用户代理
		ip := c.ClientIP()
		deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
		userAgent := c.GetHeader("User-Agent")

		resp, err := authService.Login(loginReq, ip, deviceFingerprint, userAgent)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, resp)
	case "authorization_code":
		// 处理授权码模式
		if req.Code == "" || req.ClientID == "" || req.ClientSecret == "" || req.RedirectURI == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Missing required parameters for authorization_code grant",
			})
			return
		}

		// 验证客户端
		if clientService == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Service not initialized",
			})
			return
		}

		client, err := clientService.GetByClientID(req.ClientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Client not found",
			})
			return
		}

		// 验证客户端密钥
		if client.ClientSecret != req.ClientSecret {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Invalid client secret",
			})
			return
		}

		// 验证授权码
		authCode, err := authService.ValidateAuthorizationCode(req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": err.Error(),
			})
			return
		}

		// 获取IP地址和设备指纹
		ip := c.ClientIP()
		deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

		// 生成令牌
		resp, err := authService.GenerateTokens(authCode.UserID, req.ClientID, ip, deviceFingerprint)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Failed to generate tokens",
			})
			return
		}

		c.JSON(http.StatusOK, resp)
	case "client_credentials":
		// 处理客户端凭证模式
		if req.ClientID == "" || req.ClientSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Missing required parameters for client_credentials grant",
			})
			return
		}

		// 验证客户端
		if clientService == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Service not initialized",
			})
			return
		}

		client, err := clientService.GetByClientID(req.ClientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Client not found",
			})
			return
		}

		// 验证客户端密钥
		if client.ClientSecret != req.ClientSecret {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Invalid client secret",
			})
			return
		}

		// 验证客户端状态
		if client.Status != 1 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "unauthorized_client",
				"error_description": "Client is disabled",
			})
			return
		}

		// 获取IP地址和设备指纹
		ip := c.ClientIP()
		deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

		// 生成令牌（客户端凭证模式下，userID为0表示无用户关联）
		resp, err := authService.GenerateTokens(0, req.ClientID, ip, deviceFingerprint)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Failed to generate tokens",
			})
			return
		}

		c.JSON(http.StatusOK, resp)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Unsupported grant type",
		})
	}
}

// Logout 登出端点
func Logout(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		ClientID string `json:"client_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址、设备指纹和用户代理
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	userAgent := c.GetHeader("User-Agent")

	// 从令牌中提取用户ID
	var userID uint = 0
	if req.Token != "" {
		// 验证令牌获取用户信息
		claims, err := authService.ValidateToken(req.Token, ip, deviceFingerprint)
		if err == nil {
			userID = claims.UserID
		}

		// 撤销令牌
		err = authService.RevokeToken(req.Token)
		if err != nil {
			// 令牌撤销失败不影响登出流程
		}
	}

	// 如果获取到用户ID，执行完整的登出流程
	if userID > 0 {
		err := authService.Logout(userID, ip, deviceFingerprint, userAgent)
		if err != nil {
			// 登出失败不影响响应
		}
	}

	// 返回登出成功响应
	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "登出成功",
		"data":    nil,
	})
}

// UserInfo 用户信息端点
func UserInfo(c *gin.Context) {
	// 从Authorization头获取令牌
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_request",
			"error_description": "Authorization header is required",
		})
		return
	}

	// 提取令牌
	tokenString := authHeader[7:] // 移除 "Bearer " 前缀

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Service not initialized",
		})
		return
	}

	// 获取IP地址和设备指纹
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

	// 验证令牌
	claims, err := authService.ValidateToken(tokenString, ip, deviceFingerprint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": err.Error(),
		})
		return
	}

	// 返回详细的用户信息，符合OIDC标准
	c.JSON(http.StatusOK, gin.H{
		"sub":                claims.UserID,
		"name":               claims.Username,
		"preferred_username": claims.Username,
		"email":              claims.Email,
		"email_verified":     true,
		"updated_at":         time.Now().Unix(),
		"zoneinfo":           "Asia/Shanghai",
		"locale":             "zh-CN",
	})
}

// JWKS 公钥端点
func JWKS(c *gin.Context) {
	// 返回JWKS格式的公钥
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "key:1234567890",
				"n":   "t6V6zZ7X5c4b3a2s1d0f9g8h7j6k5l4m3n2o1p0",
				"e":   "AQAB",
			},
		},
	})
}

// Introspect 令牌验证端点
func Introspect(c *gin.Context) {
	var req struct {
		Token        string `json:"token" binding:"required"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址和设备指纹
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

	// 验证令牌
	claims, err := authService.ValidateToken(req.Token, ip, deviceFingerprint)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	// 返回令牌验证结果
	c.JSON(http.StatusOK, gin.H{
		"active":     true,
		"scope":      claims.Scope,
		"client_id":  claims.ClientID,
		"user_id":    claims.UserID,
		"username":   claims.Username,
		"token_type": "Bearer",
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Unix(),
		"nbf":        time.Now().Unix(),
		"iss":        "https://sso.example.com",
		"sub":        claims.UserID,
		"aud":        claims.ClientID,
	})
}

// Register 用户注册
func Register(c *gin.Context) {
	var req model.UserRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	resp, err := authService.Register(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Login 用户登录
func Login(c *gin.Context) {
	var req model.UserLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址、设备指纹和用户代理
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	userAgent := c.GetHeader("User-Agent")

	resp, err := authService.Login(&req, ip, deviceFingerprint, userAgent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetProfile 获取用户Profile
func GetProfile(c *gin.Context) {
	// 从Authorization头获取令牌
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authorization header is required",
		})
		return
	}

	// 提取令牌
	tokenString := authHeader[7:] // 移除 "Bearer " 前缀

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址和设备指纹
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

	// 验证令牌
	claims, err := authService.ValidateToken(tokenString, ip, deviceFingerprint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token",
		})
		return
	}

	// 获取用户资料
	userProfile, err := authService.GetUserProfile(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 返回用户资料
	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    userProfile,
	})
}

// UpdateProfile 更新用户Profile
func UpdateProfile(c *gin.Context) {
	// 从Authorization头获取令牌
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authorization header is required",
		})
		return
	}

	// 提取令牌
	tokenString := authHeader[7:] // 移除 "Bearer " 前缀

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址和设备指纹
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

	// 验证令牌
	claims, err := authService.ValidateToken(tokenString, ip, deviceFingerprint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token",
		})
		return
	}

	// 解析请求参数
	var req struct {
		Nickname string `json:"nickname"`
		Avatar   string `json:"avatar"`
		Phone    string `json:"phone"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	// 更新用户资料
	userProfile, err := authService.UpdateUserProfile(claims.UserID, req.Nickname, req.Avatar, req.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 返回更新后的用户资料
	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "更新成功",
		"data":    userProfile,
	})
}

// ChangePassword 修改密码
func ChangePassword(c *gin.Context) {
	// 从Authorization头获取令牌
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authorization header is required",
		})
		return
	}

	// 提取令牌
	tokenString := authHeader[7:] // 移除 "Bearer " 前缀

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址和设备指纹
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")

	// 验证令牌
	claims, err := authService.ValidateToken(tokenString, ip, deviceFingerprint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token",
		})
		return
	}

	// 解析请求参数
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	// 修改密码
	err = authService.ChangePassword(claims.UserID, req.OldPassword, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// 撤销令牌（密码修改后的令牌失效）
	err = authService.RevokeToken(tokenString)
	if err != nil {
		// 令牌撤销失败不影响密码修改流程
	}

	// 返回密码修改成功响应
	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "密码修改成功",
		"data":    nil,
	})
}

// GetClientList 获取客户端列表
func GetClientList(c *gin.Context) {
	var req model.ClientListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	// 设置默认值
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 10
	}

	if clientService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取客户端列表
	resp, err := clientService.List(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    resp,
	})
}

// CreateClient 创建客户端
func CreateClient(c *gin.Context) {
	var req model.ClientCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if clientService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 创建客户端
	resp, err := clientService.Create(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "创建成功",
		"data":    resp,
	})
}

// UpdateClient 更新客户端
func UpdateClient(c *gin.Context) {
	var req model.ClientUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if clientService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 更新客户端
	resp, err := clientService.Update(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "更新成功",
		"data":    resp,
	})
}

// DeleteClient 删除客户端
func DeleteClient(c *gin.Context) {
	var req model.ClientDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if clientService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 删除客户端
	err := clientService.Delete(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "删除成功",
		"data":    nil,
	})
}

// GetAuditList 获取审计日志列表
func GetAuditList(c *gin.Context) {
	// 获取分页参数
	page := 1
	pageSize := 10

	if auditService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取审计日志列表
	events, total, err := auditService.GetAllEvents(page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data": gin.H{
			"list":  events,
			"total": total,
			"page":  page,
			"size":  pageSize,
		},
	})
}

// GetAuditDetail 获取审计日志详情
func GetAuditDetail(c *gin.Context) {
	// 获取ID参数
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "ID is required",
		})
		return
	}

	if auditService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 转换ID为uint
	var eventID uint
	if _, err := fmt.Sscanf(id, "%d", &eventID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid ID",
		})
		return
	}

	// 获取审计日志详情
	event, err := auditService.GetEventByID(eventID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    event,
	})
}

// GetUserAuditList 获取用户审计日志列表
func GetUserAuditList(c *gin.Context) {
	// 获取用户ID参数
	userIDStr := c.Param("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID is required",
		})
		return
	}

	// 获取分页参数
	page := 1
	pageSize := 10

	if auditService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 转换用户ID为uint
	var userID uint
	if _, err := fmt.Sscanf(userIDStr, "%d", &userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid User ID",
		})
		return
	}

	// 获取用户审计日志列表
	events, total, err := auditService.GetEventsByUserID(userID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data": gin.H{
			"list":  events,
			"total": total,
			"page":  page,
			"size":  pageSize,
		},
	})
}

// GetTypeAuditList 获取指定类型的审计日志列表
func GetTypeAuditList(c *gin.Context) {
	// 获取事件类型参数
	eventType := c.Param("event_type")
	if eventType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Event type is required",
		})
		return
	}

	// 获取分页参数
	page := 1
	pageSize := 10

	if auditService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取指定类型的审计日志列表
	events, total, err := auditService.GetEventsByEventType(eventType, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data": gin.H{
			"list":  events,
			"total": total,
			"page":  page,
			"size":  pageSize,
		},
	})
}

// GetSystemStatus 获取系统状态
func GetSystemStatus(c *gin.Context) {
	if monitorService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	status, err := monitorService.GetSystemStatus(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    status,
	})
}

// GetAuthMetrics 获取认证指标
func GetAuthMetrics(c *gin.Context) {
	if monitorService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取时间范围参数
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	metrics, err := monitorService.GetAuthMetrics(c, startTime, endTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    metrics,
	})
}

// SendVerifyCode 发送验证码
func SendVerifyCode(c *gin.Context) {
	var req model.VerifyCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	err := authService.SendVerifyCode(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "验证码发送成功",
		"data":    nil,
	})
}

// VerifyCodeLogin 验证码登录
func VerifyCodeLogin(c *gin.Context) {
	var req model.VerifyCodeLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址、设备指纹和用户代理
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	userAgent := c.GetHeader("User-Agent")

	resp, err := authService.VerifyCodeLogin(&req, ip, deviceFingerprint, userAgent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ThirdPartyLogin 第三方登录
func ThirdPartyLogin(c *gin.Context) {
	var req model.ThirdPartyLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取IP地址、设备指纹和用户代理
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	userAgent := c.GetHeader("User-Agent")

	resp, err := authService.ThirdPartyLogin(&req, ip, deviceFingerprint, userAgent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetTokenMetrics 获取令牌指标
func GetTokenMetrics(c *gin.Context) {
	if monitorService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取时间范围参数
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	metrics, err := monitorService.GetTokenMetrics(c, startTime, endTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    metrics,
	})
}

// GetAnomalyEvents 获取异常事件
func GetAnomalyEvents(c *gin.Context) {
	if monitorService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Service not initialized",
		})
		return
	}

	// 获取时间范围参数
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	// 获取严重程度参数
	severity := c.Query("severity")

	events, err := monitorService.GetAnomalyEvents(c, startTime, endTime, severity)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    10000,
		"message": "获取成功",
		"data":    events,
	})
}
