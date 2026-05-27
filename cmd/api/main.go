package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/LandcLi/LandcSSO/api"
	_ "github.com/LandcLi/LandcSSO/internal/controller/auth"
	_ "github.com/LandcLi/LandcSSO/internal/controller/client"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/audit"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/client"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/monitor"
	_ "github.com/LandcLi/LandcSSO/internal/daoimpl/token"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/audit"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/auth"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/client"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/key"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/monitor"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/session"
	_ "github.com/LandcLi/LandcSSO/internal/serviceimpl/third_party"
	"github.com/LandcLi/LandcSSO/middleware"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/logger"
	ginLog "github.com/LandcLi/landc-go/log/adapter/gin"

	// LandcUserManager - local mode: InitLUMWithConfigAndGin triggers internal init() to register controllers
	// To switch to remote mode: remove this import and use sdk.NewSDK() + userapi.RegisterUserController() instead
	landcusermanager "github.com/LandcLi/LandcUserManager"
	lumConfig "github.com/LandcLi/LandcUserManager/utility/config"

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

	// 初始化日志
	logger.InitLogger(&cfg.Log)

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

	// 创建Gin引擎
	r := gin.Default()

	// 添加中间件
	r.Use(middleware.Cors())
	ginLog.UseWithGin(r, logger.GetLogger())
	r.Use(middleware.GinMiddleware())
	r.Use(middleware.RequestLogger())

	// LandcUserManager - local mode
	// Initializes UserManager controllers and registers user routes into the shared Gin engine.
	// The internal init() registers local controller implementations for userapi.GetUserController().
	lumCfg := &lumConfig.Config{
		Server: lumConfig.ServerConfig{
			GinMode:          cfg.Server.Mode,
			EnableCORS:       false, // SSO already handles CORS
			UserDefaultRoute: true,
		},
		Database: lumConfig.DatabaseConfig{
			DSN: fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=%v&loc=%s",
				cfg.Database.User, cfg.Database.Password,
				cfg.Database.Host, cfg.Database.Port,
				cfg.Database.DBName, cfg.Database.Charset,
				cfg.Database.ParseTime, cfg.Database.Loc),
		},
		Redis: lumConfig.RedisConfig{
			Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
			PoolSize: cfg.Redis.PoolSize,
		},
	}
	err = landcusermanager.InitLUMWithConfigAndGin(lumCfg, r)
	if err != nil {
		logger.Errorf(ctx, "初始化LandcUserManager失败: %v", err)
		return
	}

	// 注册SSO路由
	api.RegisterDefaultRoutes(r)

	// 启动服务
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	logger.Infof(ctx, "服务启动在 %s", addr)
	if err := r.Run(addr); err != nil {
		logger.Errorf(ctx, "服务启动失败: %v", err)
	}
}
