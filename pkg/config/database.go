package config

import (
	"fmt"

	"github.com/LandcLi/LandcBranchGorm"
	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcLogFace"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

const DEFAULT_GROUP_NAME = "sso_db"

// DBManager 全局数据库管理器
var DBManager *dbmanager.DBManager

// MySQLDialectorCreator MySQL数据库连接创建器
type MySQLDialectorCreator struct{}

// CreateDialector 创建MySQL数据库连接
func (c *MySQLDialectorCreator) CreateDialector(config LandcBranchGorm.DBConfig) (gorm.Dialector, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.User, config.Password, config.Host, config.Port, config.DBName)
	return mysql.Open(dsn), nil
}

// InitDatabase 初始化数据库连接
func InitDatabase(cfg *DatabaseConfig) error {
	// 注册MySQL驱动
	LandcBranchGorm.RegisterDialectorCreator("mysql", &MySQLDialectorCreator{})

	// 创建主从组配置
	groupConfig := LandcBranchGorm.MasterSlaveGroupConfig{
		GroupName: DEFAULT_GROUP_NAME,
		Master: LandcBranchGorm.DBConfig{
			Host:     cfg.Host,
			Port:     cfg.Port,
			User:     cfg.User,
			Password: cfg.Password,
			DBName:   cfg.DBName,
			MaxIdle:  cfg.MaxIdleConns,
			MaxOpen:  cfg.MaxOpenConns,
			Type:     "mysql",
		},
		LoadBalance: "round-robin",
	}

	// 添加从库配置
	if cfg.MasterSlaveEnabled && len(cfg.SlaveHosts) > 0 {
		for i, slaveHost := range cfg.SlaveHosts {
			slavePort := cfg.Port // 默认使用主库端口
			if i < len(cfg.SlavePorts) {
				slavePort = cfg.SlavePorts[i]
			}

			slaveConfig := LandcBranchGorm.DBConfig{
				Host:     slaveHost,
				Port:     slavePort,
				User:     cfg.User,
				Password: cfg.Password,
				DBName:   cfg.DBName,
				MaxIdle:  cfg.MaxIdleConns,
				MaxOpen:  cfg.MaxOpenConns,
				Type:     "mysql",
			}

			groupConfig.Slaves = append(groupConfig.Slaves, slaveConfig)
		}
	}

	// 初始化DB管理器
	configs := []LandcBranchGorm.MasterSlaveGroupConfig{groupConfig}
	manager, err := LandcBranchGorm.NewDBManagerWithoutLogger(configs)
	if err != nil {
		return fmt.Errorf("初始化DB管理器失败: %v", err)
	}

	// 设置全局DB管理器
	DBManager = manager

	LandcLogFace.GetLogger().Info("数据库连接成功")
	return nil
}

// GetDBManager 获取数据库管理器
func GetDBManager() *dbmanager.DBManager {
	return DBManager
}

// GetDB 获取数据库连接（默认主库，用于写操作）
func GetDB() *gorm.DB {
	if DBManager != nil {
		db, err := DBManager.GetDB(DEFAULT_GROUP_NAME, true)
		if err != nil {
			LandcLogFace.GetLogger().Error(fmt.Sprintf("获取主库连接失败: %v", err))
			return nil
		}
		return db
	}
	return nil
}

// GetSlaveDB 获取从库连接（用于读操作）
func GetSlaveDB() *gorm.DB {
	if DBManager != nil {
		db, err := DBManager.GetDB(DEFAULT_GROUP_NAME, false)
		if err != nil {
			LandcLogFace.GetLogger().Error(fmt.Sprintf("获取从库连接失败: %v", err))
			// 如果从库连接失败，返回主库
			db, err = DBManager.GetDB(DEFAULT_GROUP_NAME, true)
			if err != nil {
				return nil
			}
			return db
		}
		return db
	}
	return nil
}

// CloseDB 关闭数据库连接
func CloseDB() error {
	if DBManager != nil {
		return DBManager.Close()
	}
	return nil
}
