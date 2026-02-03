package config

import (
	"context"
	"fmt"

	"github.com/LandcLi/LandcLogFace"

	"github.com/go-redis/redis/v8"
)

// RedisClient 全局Redis客户端
var RedisClient redis.UniversalClient

// RedisSyncClient Redis同步客户端（用于跨数据中心同步）
var RedisSyncClient redis.UniversalClient

// InitRedis 初始化Redis连接
func InitRedis(cfg *RedisConfig, multiActiveCfg *MultiActiveConfig) error {
	// 根据配置创建Redis客户端
	var client redis.UniversalClient
	if cfg.ClusterEnabled {
		// 集群模式
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    cfg.ClusterAddrs,
			Password: cfg.Password,
			PoolSize: cfg.PoolSize,
		})
	} else if cfg.SentinelEnabled {
		// 哨兵模式
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    cfg.SentinelMaster,
			SentinelAddrs: cfg.SentinelAddrs,
			Password:      cfg.Password,
			DB:            cfg.DB,
			PoolSize:      cfg.PoolSize,
		})
	} else {
		// 单节点模式
		client = redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Password: cfg.Password,
			DB:       cfg.DB,
			PoolSize: cfg.PoolSize,
		})
	}

	// 测试连接
	ctx := context.Background()
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return err
	}

	// 设置全局变量
	RedisClient = client

	// 初始化Redis同步客户端（用于跨数据中心同步）
	if multiActiveCfg != nil && multiActiveCfg.Enabled && multiActiveCfg.RedisSyncEnabled && multiActiveCfg.RedisSyncTarget != "" {
		syncClient, err := initRedisSyncClient(multiActiveCfg.RedisSyncTarget, cfg.Password, cfg.PoolSize)
		if err != nil {
			LandcLogFace.GetLogger().Error(fmt.Sprintf("Redis同步客户端初始化失败: %v", err))
			// 继续执行，不影响主客户端初始化
		} else {
			RedisSyncClient = syncClient
			LandcLogFace.GetLogger().Info("Redis同步客户端初始化成功")
		}
	}

	LandcLogFace.GetLogger().Info("Redis连接成功")
	return nil
}

// initRedisSyncClient 初始化Redis同步客户端
func initRedisSyncClient(targetAddr, password string, poolSize int) (redis.UniversalClient, error) {
	// 创建Redis同步客户端
	syncClient := redis.NewClient(&redis.Options{
		Addr:     targetAddr,
		Password: password,
		DB:       0,
		PoolSize: poolSize,
	})

	// 测试连接
	ctx := context.Background()
	_, err := syncClient.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return syncClient, nil
}

// GetRedis 获取Redis客户端
func GetRedis() redis.UniversalClient {
	return RedisClient
}

// GetRedisSync 获取Redis同步客户端
func GetRedisSync() redis.UniversalClient {
	return RedisSyncClient
}

// SyncRedisData 同步Redis数据到目标数据中心
func SyncRedisData(key string, value interface{}) error {
	if RedisSyncClient == nil {
		return nil // 同步客户端未初始化，跳过同步
	}

	ctx := context.Background()
	return RedisSyncClient.Set(ctx, key, value, 0).Err()
}
