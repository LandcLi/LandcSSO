package tests

import (
	"testing"

	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/internal/service"
	"github.com/LandcLi/LandcSSO/pkg/config"
)

func TestAuditService_GetAllEvents(t *testing.T) {
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

	// 创建仓库
	auditRepo := repository.NewAuditRepository(config.DBManager)

	// 创建审计服务
	auditService := service.NewAuditService(auditRepo)

	// 测试获取所有审计事件
	events, total, err := auditService.GetAllEvents(1, 10)
	if err != nil {
		t.Fatalf("GetAllEvents() 失败: %v", err)
	}

	if events == nil {
		t.Errorf("GetAllEvents() 返回 nil")
	}

	if total < 0 {
		t.Errorf("total 期望 >= 0, 实际 %d", total)
	}
}

func TestAuditService_GetEventsByUserID(t *testing.T) {
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

	// 创建仓库
	auditRepo := repository.NewAuditRepository(config.DBManager)

	// 创建审计服务
	auditService := service.NewAuditService(auditRepo)

	// 测试获取用户的审计事件
	userID := uint(1) // 管理员用户ID
	events, total, err := auditService.GetEventsByUserID(userID, 1, 10)
	if err != nil {
		t.Fatalf("GetEventsByUserID() 失败: %v", err)
	}

	if events == nil {
		t.Errorf("GetEventsByUserID() 返回 nil")
	}

	if total < 0 {
		t.Errorf("total 期望 >= 0, 实际 %d", total)
	}
}

func TestAuditService_GetEventsByEventType(t *testing.T) {
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

	// 创建仓库
	auditRepo := repository.NewAuditRepository(config.DBManager)

	// 创建审计服务
	auditService := service.NewAuditService(auditRepo)

	// 测试获取指定类型的审计事件
	eventType := "login"
	events, total, err := auditService.GetEventsByEventType(eventType, 1, 10)
	if err != nil {
		t.Fatalf("GetEventsByEventType() 失败: %v", err)
	}

	if events == nil {
		t.Errorf("GetEventsByEventType() 返回 nil")
	}

	if total < 0 {
		t.Errorf("total 期望 >= 0, 实际 %d", total)
	}
}
