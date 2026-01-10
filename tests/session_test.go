package tests

import (
	"testing"

	"github.com/LandcLi/LandcSSO/internal/service"
	"github.com/LandcLi/LandcSSO/pkg/config"
)

func TestSessionService_CreateSession(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 创建会话服务
	sessionService := service.NewSessionService()

	// 测试创建会话
	sessionID, err := sessionService.CreateSession(1, "admin", map[string]interface{}{
		"role":  "admin",
		"email": "admin@example.com",
	})

	if err != nil {
		t.Fatalf("CreateSession() 失败: %v", err)
	}

	if sessionID == "" {
		t.Error("SessionID 为空")
	}
}

func TestSessionService_GetSession(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 创建会话服务
	sessionService := service.NewSessionService()

	// 创建会话
	sessionID, err := sessionService.CreateSession(1, "admin", map[string]interface{}{
		"role":  "admin",
		"email": "admin@example.com",
	})

	if err != nil {
		t.Fatalf("CreateSession() 失败: %v", err)
	}

	// 获取会话
	session, err := sessionService.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession() 失败: %v", err)
	}

	if session.UserID != 1 {
		t.Errorf("UserID 期望 1, 实际 %d", session.UserID)
	}

	if session.Username != "admin" {
		t.Errorf("Username 期望 'admin', 实际 '%s'", session.Username)
	}
}

func TestSessionService_UpdateSession(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 创建会话服务
	sessionService := service.NewSessionService()

	// 创建会话
	sessionID, err := sessionService.CreateSession(1, "admin", map[string]interface{}{
		"role":  "admin",
		"email": "admin@example.com",
	})

	if err != nil {
		t.Fatalf("CreateSession() 失败: %v", err)
	}

	// 更新会话
	err = sessionService.UpdateSession(sessionID, map[string]interface{}{
		"role":       "superadmin",
		"email":      "admin@example.com",
		"last_login": "2026-01-10",
	})

	if err != nil {
		t.Fatalf("UpdateSession() 失败: %v", err)
	}

	// 获取会话
	session, err := sessionService.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession() 失败: %v", err)
	}

	if session.Data["role"] != "superadmin" {
		t.Errorf("Role 期望 'superadmin', 实际 '%v'", session.Data["role"])
	}
}

func TestSessionService_DeleteSession(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 创建会话服务
	sessionService := service.NewSessionService()

	// 创建会话
	sessionID, err := sessionService.CreateSession(1, "admin", map[string]interface{}{
		"role":  "admin",
		"email": "admin@example.com",
	})

	if err != nil {
		t.Fatalf("CreateSession() 失败: %v", err)
	}

	// 删除会话
	err = sessionService.DeleteSession(sessionID)
	if err != nil {
		t.Fatalf("DeleteSession() 失败: %v", err)
	}

	// 尝试获取已删除的会话
	_, err = sessionService.GetSession(sessionID)
	if err == nil {
		t.Error("GetSession() 应该失败，因为会话已删除")
	}
}

func TestSessionService_DeleteUserSessions(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 初始化Redis
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		t.Skipf("初始化Redis失败: %v, 跳过测试", err)
	}

	// 创建会话服务
	sessionService := service.NewSessionService()

	// 创建多个会话
	for i := 0; i < 3; i++ {
		_, err := sessionService.CreateSession(1, "admin", map[string]interface{}{
			"role":  "admin",
			"email": "admin@example.com",
		})

		if err != nil {
			t.Fatalf("CreateSession() 失败: %v", err)
		}
	}

	// 删除用户的所有会话
	err = sessionService.DeleteUserSessions(1)
	if err != nil {
		t.Fatalf("DeleteUserSessions() 失败: %v", err)
	}
}
