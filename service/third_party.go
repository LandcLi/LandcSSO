package service

import (
	"context"
	"fmt"
	"sync"
)

// -------------------------- 对外暴露的核心接口 --------------------------
// ThirdPartyAdapter 第三方适配器核心接口（用户自定义适配器需实现此接口）
type ThirdPartyAdapter interface {
	ValidateRedirectURI(ctx context.Context, redirectURI string) error
	GenerateAuthURL(ctx context.Context, params map[string]string) (string, error)
	RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error)
	FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, error)
}

// AdapterFactory 适配器工厂接口（屏蔽不同Config的创建逻辑）
// 库默认适配器/用户自定义适配器都需实现此接口
type AdapterFactory interface {
	// Type 返回适配器类型（如"wechat"），与配置中的key对应
	Type() string
	// Create 接收通用配置（map[string]interface{}），创建适配器实例
	// 内部自行解析配置为专属Config，屏蔽外部感知
	Create(config map[string]interface{}) (ThirdPartyAdapter, error)
}

// -------------------------- 工厂注册（用于自动初始化） --------------------------
var (
	factories       = make(map[string]AdapterFactory) // key=适配器类型（如"wechat"）
	factoriesRWLock sync.RWMutex
)

// RegisterAdapterFactory 注册适配器工厂（用户可调用此方法覆盖默认工厂）
func RegisterAdapterFactory(factory AdapterFactory) {
	factoriesRWLock.Lock()
	defer factoriesRWLock.Unlock()
	factories[factory.Type()] = factory
}

// getFactory 获取适配器工厂（内部使用）
func getFactory(adapterType string) (AdapterFactory, bool) {
	factoriesRWLock.RLock()
	defer factoriesRWLock.RUnlock()
	factory, ok := factories[adapterType]
	return factory, ok
}

// GetFactory 获取适配器工厂（对外暴露）
func GetFactory(adapterType string) (AdapterFactory, bool) {
	return getFactory(adapterType)
}

// -------------------------- 适配器注册（原有逻辑，对外暴露） --------------------------
var (
	adapters       = make(map[string]ThirdPartyAdapter)
	adaptersRWLock sync.RWMutex
)

// RegisterThirdPartyAdapter 注册适配器实例（用户可直接注册实例覆盖）
// 对外暴露，兼容原有逻辑
func RegisterThirdPartyAdapter(adapterType string, adapter ThirdPartyAdapter) {
	adaptersRWLock.Lock()
	defer adaptersRWLock.Unlock()
	adapters[adapterType] = adapter
}

// GetThirdPartyAdapter 获取适配器实例（对外暴露）
func GetThirdPartyAdapter(adapterType string) (ThirdPartyAdapter, bool) {
	adaptersRWLock.RLock()
	defer adaptersRWLock.RUnlock()
	adapter, ok := adapters[adapterType]
	return adapter, ok
}

// InitWithConfig 库对外暴露的核心初始化函数
// 用户只需传入通用配置，自动创建并注册所有适配器
// 屏蔽Config解析、工厂创建等细节
func InitWithConfig(globalConfig *ThirdPartyGlobalConfig) error {
	// 遍历配置中的所有第三方类型（如"wechat"）
	for adapterType, config := range globalConfig.ThirdParty {
		// 1. 获取对应工厂（默认/用户自定义）
		factory, ok := getFactory(adapterType)
		if !ok {
			return fmt.Errorf("factory not registered for type %s", adapterType)
		}

		// 2. 通过工厂创建适配器（内部解析Config，屏蔽细节）
		adapter, err := factory.Create(config)
		if err != nil {
			return fmt.Errorf("failed to create adapter %s: %w", adapterType, err)
		}

		// 3. 注册适配器实例（如果不存在）
		if _, exists := GetThirdPartyAdapter(adapterType); !exists {
			RegisterThirdPartyAdapter(adapterType, adapter)
		}
	}
	return nil
}

// ThirdPartyGlobalConfig 库对外暴露的通用配置
// 用户只需在ThirdParty节点下按类型配置参数，无需感知内部Config
type ThirdPartyGlobalConfig struct {
	ThirdParty map[string]map[string]interface{} `mapstructure:"third_party"` // key=适配器类型（如"wechat"），value=该类型的配置参数
}
