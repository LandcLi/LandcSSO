package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/LandcLi/LandcSSO/internal/api"
	"github.com/LandcLi/LandcSSO/internal/middleware"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/internal/service"
	"github.com/LandcLi/LandcSSO/pkg/config"

	"github.com/LandcLi/LandcLogFace"

	"github.com/LandcLi/LandcSSO/pkg/logger"
	"github.com/gin-gonic/gin"
)

func main() {
	ctx := context.Background()
	// 解析命令行参数
	configPath := flag.String("config", "config.yml", "配置文件路径")
	flag.Parse()

	// 初始化配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	logger.InitLogger(cfg)
	// 初始化数据库连接
	err = config.InitDatabase(&cfg.Database)
	if err != nil {
		logger.Errorf(ctx, "初始化数据库失败: %v", err)
		return
	}

	// 初始化Redis连接
	err = config.InitRedis(&cfg.Redis, &cfg.MultiActive)
	if err != nil {
		logger.Errorf(ctx, "初始化Redis失败: %v", err)
		return
	}

	// 初始化仓库
	userRepo := repository.NewUserRepository(config.GetDB(), config.GetRedis())
	tokenRepo := repository.NewTokenRepository(config.GetDB(), config.GetRedis())
	clientRepo := repository.NewClientRepository(config.GetDB())
	auditRepo := repository.NewAuditRepository(config.GetDB())
	loginHistoryRepo := repository.NewLoginHistoryRepository(config.GetDB())
	trustedDeviceRepo := repository.NewTrustedDeviceRepository(config.GetDB(), config.GetRedis())
	monitorRepo := repository.NewMonitorRepository(config.GetDB())

	// 初始化服务
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, tokenRepo, loginHistoryRepo, trustedDeviceRepo, cfg)
	clientService := service.NewClientService(clientRepo, cfg)
	monitorService := service.NewMonitorService(monitorRepo, auditService, cfg)

	// 设置服务到API模块
	api.SetAuthService(authService)
	api.SetClientService(clientService)
	api.SetAuditService(auditService)
	api.SetMonitorService(monitorService)

	// 创建Gin引擎
	r := gin.Default()

	// 添加中间件
	r.Use(middleware.Cors())
	LandcLogFace.UseWithGin(r, logger.GetLogger())
	r.Use(middleware.GinMiddleware())

	// 注册路由
	api.RegisterRoutes(r)

	// 启动服务
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	logger.Infof(ctx, "服务启动在 %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Errorf(ctx, "服务启动失败: %v", err)
	}
}
