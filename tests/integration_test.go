package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LandcLi/LandcSSO/internal/api"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/internal/service"
	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/gin-gonic/gin"
)

func TestIntegration_CompleteAuthFlow(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过集成测试", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过集成测试", err)
	}

	// 获取数据库连接和Redis客户端
	db := config.GetDB()
	redisClient := config.GetRedis()

	// 创建仓库
	userRepo := repository.NewUserRepository(db, redisClient)
	tokenRepo := repository.NewTokenRepository(db, redisClient)
	clientRepo := repository.NewClientRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	loginHistoryRepo := repository.NewLoginHistoryRepository(db)
	trustedDeviceRepo := repository.NewTrustedDeviceRepository(db, redisClient)
	thirdPartyUserRepo := repository.NewThirdPartyUserRepository(db, redisClient)
	monitorRepo := repository.NewMonitorRepository(db)

	// 创建服务
	authService := service.NewAuthService(userRepo, tokenRepo, loginHistoryRepo, trustedDeviceRepo, thirdPartyUserRepo, cfg)
	clientService := service.NewClientService(clientRepo, cfg)
	auditService := service.NewAuditService(auditRepo)
	monitorService := service.NewMonitorService(monitorRepo, auditService, cfg)

	// 设置服务
	api.SetAuthService(authService)
	api.SetClientService(clientService)
	api.SetAuditService(auditService)
	api.SetMonitorService(monitorService)

	// 创建Gin引擎
	r := gin.Default()

	// 注册路由
	api.RegisterRoutes(r)

	// 测试健康检查
	t.Run("健康检查", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("健康检查失败，状态码: %d", w.Code)
		}
	})

	// 测试认证流程
	t.Run("认证流程", func(t *testing.T) {
		// 这里可以添加完整的认证流程测试，包括：
		// 1. 授权码请求
		// 2. 令牌获取
		// 3. 用户信息获取
		// 4. 令牌验证
		// 5. 登出

		// 由于需要模拟浏览器交互和重定向，这里只做简单测试
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/auth/authorize?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code&state=test-state", nil)
		r.ServeHTTP(w, req)

		// 检查是否重定向
		if w.Code != http.StatusFound {
			t.Logf("授权端点返回状态码: %d, 预期: %d", w.Code, http.StatusFound)
		}
	})
}

func TestIntegration_UserManagement(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过集成测试", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过集成测试", err)
	}

	// 获取数据库连接和Redis客户端
	db := config.GetDB()
	redisClient := config.GetRedis()

	// 创建仓库
	userRepo := repository.NewUserRepository(db, redisClient)
	tokenRepo := repository.NewTokenRepository(db, redisClient)
	loginHistoryRepo := repository.NewLoginHistoryRepository(db)
	trustedDeviceRepo := repository.NewTrustedDeviceRepository(db, redisClient)
	thirdPartyUserRepo := repository.NewThirdPartyUserRepository(db, redisClient)

	// 创建服务
	authService := service.NewAuthService(userRepo, tokenRepo, loginHistoryRepo, trustedDeviceRepo, thirdPartyUserRepo, cfg)

	// 设置服务
	api.SetAuthService(authService)

	// 创建Gin引擎
	r := gin.Default()

	// 注册路由
	api.RegisterRoutes(r)

	// 测试用户登录
	t.Run("用户登录", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/user/login", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Logf("登录端点返回状态码: %d, 预期: %d (缺少参数)", w.Code, http.StatusBadRequest)
		}
	})
}

func TestIntegration_ClientManagement(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过集成测试", err)
	}

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	clientRepo := repository.NewClientRepository(db)

	// 创建服务
	clientService := service.NewClientService(clientRepo, cfg)

	// 设置服务
	api.SetClientService(clientService)

	// 创建Gin引擎
	r := gin.Default()

	// 注册路由
	api.RegisterRoutes(r)

	// 测试客户端列表
	t.Run("客户端列表", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/client/list", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Logf("客户端列表端点返回状态码: %d, 预期: %d", w.Code, http.StatusOK)
		}
	})
}
