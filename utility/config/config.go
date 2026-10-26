package config

import (
	"os"
	"time"

	framecache "github.com/LandcLi/landc-go/frame/pkg/cache"
	framedb "github.com/LandcLi/landc-go/frame/pkg/db"
	"github.com/LandcLi/landc-go/log/facade"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v2"
	"gorm.io/gorm"
)

var globalConfig *Config

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	JWT      JWTConfig      `yaml:"jwt"`
	Mail     MailConfig     `yaml:"mail"`
	SMS      SMSConfig      `yaml:"sms"`
	Frontend FrontendConfig `yaml:"frontend"`
	// 注意：log 段由框架（landc-go/frame/pkg/config）解析，
	// 本结构不再重复定义，避免同一配置项出现两个不兼容的类型定义
	// （框架为 string 级别，历史实现为 int 枚举，互相破坏解析）。
	UserManager UserManagerConfig `yaml:"user_manager"`
	Seed        SeedConfig        `yaml:"seed"`
	// TokenCleanup 过期令牌/授权码的定时物理清理配置。
	TokenCleanup TokenCleanupConfig `yaml:"token_cleanup"`
	// ThirdParty 第三方登录配置（key=适配器类型，value=该类型配置项）
	ThirdParty map[string]map[string]interface{} `yaml:"third_party"`
}

// 用户中心的接入方式。
const (
	// UserManagerModeLocal 进程内复用 LandcUserManager（单二进制部署，推荐）
	UserManagerModeLocal = "local"
	// UserManagerModeRemote 通过 HTTP 调用独立部署的 LandcUserManager
	UserManagerModeRemote = "remote"
)

// UserManagerConfig 描述用户中心（LandcUserManager）的接入方式。
type UserManagerConfig struct {
	// Mode: local | remote，默认 local
	Mode string `yaml:"mode"`
	// BaseURL 仅在 remote 模式使用，例如 http://127.0.0.1:18081
	BaseURL string `yaml:"baseUrl"`
	// ServiceKey 服务间调用凭证，remote 模式下随请求以 X-Service-Key 头发给 LUM。
	//
	// 用途：OIDC /userinfo 要按令牌里的 sub 读取用户档案，这是服务间调用，
	// 手上没有「当前登录用户」的 token，走用户 JWT 无处可带。LUM 已启用鉴权，
	// 必须靠这个共享密钥放行。必须与 LUM 的 service_auth.key 完全一致；
	// 留空则不带该头，/auth/userinfo 会因 LUM 返回 401 而报 502。
	ServiceKey string `yaml:"serviceKey"`
}

// SeedConfig 首次启动的种子数据。生产环境请关闭。
type SeedConfig struct { // Enabled 为 true 且 clients 表中不存在该 client_id 时，自动创建一个示例客户端，
	// 便于新环境立刻走通授权码 / 客户端凭证流程。
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	// RedirectURIs 示例客户端允许的回调地址（精确匹配）
	RedirectURIs []string `yaml:"redirectUris"`
	Scope        string   `yaml:"scope"`
}

// IsLocal 用户中心是否运行在同一进程内。
func (c UserManagerConfig) IsLocal() bool {
	return c.Mode == "" || c.Mode == UserManagerModeLocal
}

// TokenCleanupConfig 过期令牌/授权码的定时物理清理策略。
//
// tokens 与 authorization_codes 两张表此前只有写入、从不清理：每次 login /
// refresh / 授权码签发都 INSERT 一条，长期运行会无限增长。这里用后台定时任务
// 物理删除已过期（refresh 已过期）或已撤销的令牌，以及过期授权码。
type TokenCleanupConfig struct {
	// Enabled 为 true 时启动后台清理任务，默认 true。
	Enabled bool `yaml:"enabled"`
	// IntervalSeconds 清理间隔（秒），默认 3600（1 小时）。
	IntervalSeconds int `yaml:"interval_seconds"`
}

// Interval 返回清理间隔；未配置或非法时回落默认 1 小时。
func (c TokenCleanupConfig) Interval() time.Duration {
	if c.IntervalSeconds <= 0 {
		return time.Hour
	}
	return time.Duration(c.IntervalSeconds) * time.Second
}

// FrontendConfig 前端回调配置
type FrontendConfig struct {
	// CallbackURL 第三方 OAuth 回调成功后重定向的前端地址（token 通过 URL fragment 传递）
	CallbackURL string `yaml:"callback_url"`
}

type ServerConfig struct {
	Port int      `yaml:"port"`
	Host string   `yaml:"host"`
	Mode string   `yaml:"mode"`
	Cors []string `yaml:"cors"` // 允许的跨域 Origin 白名单，空表示不允许跨域
}

type DatabaseConfig struct {
	Driver    string `yaml:"driver"`
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	User      string `yaml:"user"`
	Password  string `yaml:"password"`
	DBName    string `yaml:"dbname"`
	Charset   string `yaml:"charset"`
	ParseTime bool   `yaml:"parseTime"`
	Loc       string `yaml:"loc"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	PoolSize int    `yaml:"poolSize"`
}

type JWTConfig struct {
	Secret                string `yaml:"secret"`
	Issuer                string `yaml:"issuer"`
	AccessTokenExpiry     int    `yaml:"accessTokenExpiry"`
	RefreshTokenExpiry    int    `yaml:"refreshTokenExpiry"`
	PrivateKeyPath        string `yaml:"privateKeyPath"`
	PublicKeyPath         string `yaml:"publicKeyPath"`
	SigningMethod         string `yaml:"signingMethod"`
	MaxConcurrentSessions int    `yaml:"maxConcurrentSessions"`
}

type MailConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	UseSSL   bool   `yaml:"useSSL"`
}

type SMSConfig struct {
	Provider  string            `yaml:"provider"`
	APIKey    string            `yaml:"apiKey"`
	SecretKey string            `yaml:"secretKey"`
	SignName  string            `yaml:"signName"`
	Templates map[string]string `yaml:"templates"`
}

func LoadConfig(path string) (*Config, error) {
	// 优先从指定路径加载，找不到时递归搜索父目录
	data, err := os.ReadFile(path)
	if err != nil && os.IsNotExist(err) {
		// 尝试在各级父目录中查找（最多上溯 5 层）
		for i := 1; i <= 5; i++ {
			candidate := path
			for j := 0; j < i; j++ {
				candidate = "../" + candidate
			}
			data, err = os.ReadFile(candidate)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 环境变量覆盖敏感配置（生产环境推荐注入，避免写入配置文件）
	// LANDC_JWT_SECRET 为 landc-go 框架统一命名，SSO_JWT_SECRET 为兼容旧配置保留
	if v := os.Getenv("LANDC_JWT_SECRET"); v != "" {
		cfg.JWT.Secret = v
	} else if v := os.Getenv("SSO_JWT_SECRET"); v != "" {
		cfg.JWT.Secret = v
	}
	if v := os.Getenv("SSO_JWT_PRIVATE_KEY"); v != "" {
		cfg.JWT.PrivateKeyPath = v
	}
	if v := os.Getenv("SSO_JWT_PUBLIC_KEY"); v != "" {
		cfg.JWT.PublicKeyPath = v
	}

	applyDefaults(&cfg)

	globalConfig = &cfg
	return &cfg, nil
}

// Init 显式加载配置，幂等。
// 启动阶段调用它可以把「配置文件缺失/格式错误」变成明确的启动错误，
// 而不是等到第一次 GetConfig() 才发现。
func Init(path string) error {
	if globalConfig != nil {
		return nil
	}
	_, err := LoadConfig(path)
	return err
}

// applyDefaults 填充未显式配置项的默认值。
func applyDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.UserManager.Mode == "" {
		cfg.UserManager.Mode = UserManagerModeLocal
	}
	if cfg.UserManager.Mode == UserManagerModeRemote && cfg.UserManager.BaseURL == "" {
		cfg.UserManager.BaseURL = "http://127.0.0.1:18081"
	}
	if cfg.JWT.SigningMethod == "" {
		cfg.JWT.SigningMethod = "HS256"
	}
	if cfg.JWT.AccessTokenExpiry == 0 {
		cfg.JWT.AccessTokenExpiry = 1800
	}
	if cfg.JWT.RefreshTokenExpiry == 0 {
		cfg.JWT.RefreshTokenExpiry = 86400
	}
	if cfg.Seed.Enabled {
		if cfg.Seed.ClientID == "" {
			cfg.Seed.ClientID = "landc-sso-demo"
		}
		if cfg.Seed.Scope == "" {
			cfg.Seed.Scope = "openid profile email"
		}
		if len(cfg.Seed.RedirectURIs) == 0 {
			cfg.Seed.RedirectURIs = []string{"http://localhost:3000/callback"}
		}
	}
}

// AllowedOrigins 返回 CORS 允许的 Origin 白名单
func (c *Config) AllowedOrigins() []string {
	if c == nil {
		return nil
	}
	return c.Server.Cors
}

func GetConfig() *Config {
	if globalConfig == nil {
		cfg, err := LoadConfig("config.yaml")
		if err == nil {
			globalConfig = cfg
		} else {
			facade.Errorf("load config failed: %v", err)
		}
	}
	return globalConfig
}

// GetDB delegates to the framework's framedb.
func GetDB() *gorm.DB {
	return framedb.GetDB()
}

// GetRedis delegates to the framework's Redis cache.
func GetRedis() *redis.Client {
	rc := framecache.GetRedis()
	if rc == nil {
		return nil
	}
	return rc
}
