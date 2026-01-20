package tests

import (
	"testing"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/internal/service"
	"github.com/LandcLi/LandcSSO/pkg/config"
)

func TestAuthService_Login(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 获取Redis客户端
	redisClient := config.GetRedis()

	// 创建仓库
	userRepo := repository.NewUserRepository(config.DBManager, redisClient)
	tokenRepo := repository.NewTokenRepository(config.DBManager, redisClient)
	loginHistoryRepo := repository.NewLoginHistoryRepository(config.DBManager)
	trustedDeviceRepo := repository.NewTrustedDeviceRepository(config.DBManager, redisClient)
	thirdPartyUserRepo := repository.NewThirdPartyUserRepository(config.DBManager, redisClient)

	// 创建认证服务
	authService := service.NewAuthService(userRepo, tokenRepo, loginHistoryRepo, trustedDeviceRepo, thirdPartyUserRepo, cfg)

	// 测试登录
	testCases := []struct {
		name     string
		username string
		password string
		expected bool
	}{
		{"测试成功登录", "admin", "123456", true},
		{"测试失败登录", "admin", "wrongpassword", false},
		{"测试不存在用户", "nonexistent", "123456", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &model.UserLoginRequest{
				Username: tc.username,
				Password: tc.password,
			}

			_, err := authService.Login(req, "127.0.0.1", "test-device", "test-user-agent")
			if (err == nil) != tc.expected {
				t.Errorf("Login() 期望 %v, 实际 %v, 错误: %v", tc.expected, err == nil, err)
			}
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 获取Redis客户端
	redisClient := config.GetRedis()

	// 创建仓库
	userRepo := repository.NewUserRepository(config.DBManager, redisClient)
	tokenRepo := repository.NewTokenRepository(config.DBManager, redisClient)
	loginHistoryRepo := repository.NewLoginHistoryRepository(config.DBManager)
	trustedDeviceRepo := repository.NewTrustedDeviceRepository(config.DBManager, redisClient)
	thirdPartyUserRepo := repository.NewThirdPartyUserRepository(config.DBManager, redisClient)

	// 创建认证服务
	authService := service.NewAuthService(userRepo, tokenRepo, loginHistoryRepo, trustedDeviceRepo, thirdPartyUserRepo, cfg)

	// 测试注册
	testCases := []struct {
		name     string
		username string
		email    string
		password string
		expected bool
	}{
		{"测试成功注册", "testuser", "test@example.com", "123456", true},
		{"测试用户名已存在", "admin", "test2@example.com", "123456", false},
		{"测试邮箱已存在", "testuser2", "admin@example.com", "123456", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &model.UserRegisterRequest{
				Username: tc.username,
				Email:    tc.email,
				Password: tc.password,
			}

			_, err := authService.Register(req)
			if (err == nil) != tc.expected {
				t.Errorf("Register() 期望 %v, 实际 %v, 错误: %v", tc.expected, err == nil, err)
			}
		})
	}
}

func TestAuthService_ValidateToken(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化数据库
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		t.Skipf("初始化数据库失败: %v, 跳过测试", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 获取Redis客户端
	redisClient := config.GetRedis()

	// 创建仓库
	userRepo := repository.NewUserRepository(config.DBManager, redisClient)
	tokenRepo := repository.NewTokenRepository(config.DBManager, redisClient)
	loginHistoryRepo := repository.NewLoginHistoryRepository(config.DBManager)
	trustedDeviceRepo := repository.NewTrustedDeviceRepository(config.DBManager, redisClient)
	thirdPartyUserRepo := repository.NewThirdPartyUserRepository(config.DBManager, redisClient)

	// 创建认证服务
	authService := service.NewAuthService(userRepo, tokenRepo, loginHistoryRepo, trustedDeviceRepo, thirdPartyUserRepo, cfg)

	// 测试登录获取令牌
	loginReq := &model.UserLoginRequest{
		Username: "admin",
		Password: "123456",
	}

	tokenResp, err := authService.Login(loginReq, "127.0.0.1", "test-device", "test-user-agent")
	if err != nil {
		t.Fatalf("Login() 失败: %v", err)
	}

	// 验证令牌
	claims, err := authService.ValidateToken(tokenResp.AccessToken, "127.0.0.1", "test-device")
	if err != nil {
		t.Fatalf("ValidateToken() 失败: %v", err)
	}

	if claims.UserID != 1 {
		t.Errorf("UserID 期望 1, 实际 %d", claims.UserID)
	}
}
