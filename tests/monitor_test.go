package tests

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/gin-gonic/gin"
)

func TestMonitorService_GetSystemStatus(t *testing.T) {
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

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	monitorRepo := repository.NewMonitorRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// 创建审计服务
	auditService := service.NewAuditService(auditRepo)

	// 创建监控服务
	monitorService := service.NewMonitorService(monitorRepo, auditService, cfg)

	// 创建Gin上下文
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// 测试获取系统状态
	status, err := monitorService.GetSystemStatus(c)
	if err != nil {
		t.Fatalf("GetSystemStatus() 失败: %v", err)
	}

	if status == nil {
		t.Errorf("GetSystemStatus() 返回 nil")
	}
}

func TestMonitorService_GetAuthMetrics(t *testing.T) {
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

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	monitorRepo := repository.NewMonitorRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// 创建审计服务
	auditService := service.NewAuditService(auditRepo)

	// 创建监控服务
	monitorService := service.NewMonitorService(monitorRepo, auditService, cfg)

	// 创建Gin上下文
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// 测试获取认证指标
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	metrics, err := monitorService.GetAuthMetrics(c, startTime, endTime)
	if err != nil {
		t.Fatalf("GetAuthMetrics() 失败: %v", err)
	}

	if metrics == nil {
		t.Errorf("GetAuthMetrics() 返回 nil")
	}
}

func TestMonitorService_GetTokenMetrics(t *testing.T) {
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

	// 获取数据库连接
	db := config.GetDB()

	// 创建仓库
	monitorRepo := repository.NewMonitorRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// 创建审计服务
	auditService := service.NewAuditService(auditRepo)

	// 创建监控服务
	monitorService := service.NewMonitorService(monitorRepo, auditService, cfg)

	// 创建Gin上下文
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// 测试获取令牌指标
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	metrics, err := monitorService.GetTokenMetrics(c, startTime, endTime)
	if err != nil {
		t.Fatalf("GetTokenMetrics() 失败: %v", err)
	}

	if metrics == nil {
		t.Errorf("GetTokenMetrics() 返回 nil")
	}
}
