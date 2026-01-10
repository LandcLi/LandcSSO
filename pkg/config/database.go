package config

import (
	"fmt"
	"time"

	"github.com/LandcLi/LandcLogFace"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// DB 全局数据库连接（主库）
var DB *gorm.DB

// DBSlaves 从库连接列表
var DBSlaves []*gorm.DB

// InitDatabase 初始化数据库连接
func InitDatabase(cfg *DatabaseConfig) error {
	// 构建主库DSN
	masterDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=%t&loc=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName, cfg.Charset, cfg.ParseTime, cfg.Loc)

	// 配置GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true, // 使用单数表名
		},
	}

	// 连接主库
	masterDB, err := gorm.Open(mysql.Open(masterDSN), gormConfig)
	if err != nil {
		return err
	}

	// 配置主库连接池
	masterSQLDB, err := masterDB.DB()
	if err != nil {
		return err
	}

	// 设置连接池参数
	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns <= 0 {
		maxIdleConns = 10 // 默认值
	}

	maxOpenConns := cfg.MaxOpenConns
	if maxOpenConns <= 0 {
		maxOpenConns = 100 // 默认值
	}

	connMaxLifetimeHour := cfg.ConnMaxLifetimeHour
	if connMaxLifetimeHour <= 0 {
		connMaxLifetimeHour = 1 // 默认值
	}

	masterSQLDB.SetMaxIdleConns(maxIdleConns)                                      // 最大空闲连接数
	masterSQLDB.SetMaxOpenConns(maxOpenConns)                                      // 最大打开连接数
	masterSQLDB.SetConnMaxLifetime(time.Duration(connMaxLifetimeHour) * time.Hour) // 连接最大生命周期

	// 设置全局变量
	DB = masterDB

	// 初始化从库连接
	if cfg.MasterSlaveEnabled && len(cfg.SlaveHosts) > 0 {
		for i, slaveHost := range cfg.SlaveHosts {
			slavePort := cfg.Port // 默认使用主库端口
			if i < len(cfg.SlavePorts) {
				slavePort = cfg.SlavePorts[i]
			}

			// 构建从库DSN
			slaveDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=%t&loc=%s",
				cfg.User, cfg.Password, slaveHost, slavePort, cfg.DBName, cfg.Charset, cfg.ParseTime, cfg.Loc)

			// 连接从库
			slaveDB, err := gorm.Open(mysql.Open(slaveDSN), gormConfig)
			if err != nil {
				LandcLogFace.GetLogger().Error(fmt.Sprintf("从库连接失败: %v", err))
				continue
			}

			// 配置从库连接池
			slaveSQLDB, err := slaveDB.DB()
			if err != nil {
				LandcLogFace.GetLogger().Error(fmt.Sprintf("从库连接池配置失败: %v", err))
				continue
			}

			// 设置从库连接池参数
			slaveSQLDB.SetMaxIdleConns(maxIdleConns)
			slaveSQLDB.SetMaxOpenConns(maxOpenConns)
			slaveSQLDB.SetConnMaxLifetime(time.Duration(connMaxLifetimeHour) * time.Hour)

			// 添加到从库列表
			DBSlaves = append(DBSlaves, slaveDB)
			LandcLogFace.GetLogger().Info(fmt.Sprintf("从库连接成功: %s:%d", slaveHost, slavePort))
		}
	}

	LandcLogFace.GetLogger().Info("数据库连接成功")
	return nil
}

// GetDB 获取数据库连接（默认主库，用于写操作）
func GetDB() *gorm.DB {
	return DB
}

// GetSlaveDB 获取从库连接（用于读操作）
func GetSlaveDB() *gorm.DB {
	if len(DBSlaves) > 0 {
		// 简单轮询选择从库
		return DBSlaves[0]
	}
	// 如果没有从库，返回主库
	return DB
}

// GetAllDBs 获取所有数据库连接
func GetAllDBs() []*gorm.DB {
	dbs := []*gorm.DB{DB}
	dbs = append(dbs, DBSlaves...)
	return dbs
}
