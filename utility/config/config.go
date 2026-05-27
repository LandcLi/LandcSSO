package config

import (
	"os"

	"github.com/LandcLi/landc-go/log/facade"
	"gopkg.in/yaml.v2"
)

var globalConfig *Config

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Database    DatabaseConfig    `yaml:"database"`
	Redis       RedisConfig       `yaml:"redis"`
	JWT         JWTConfig         `yaml:"jwt"`
	Log         facade.LogConfig  `yaml:"log"`
	MultiActive MultiActiveConfig `yaml:"multiActive"`
	Mail        MailConfig        `yaml:"mail"`
	SMS         SMSConfig         `yaml:"sms"`
	ThirdParty  ThirdPartyConfig  `yaml:"thirdParty"`
}

// ThirdPartyConfig 第三方登录配置
type ThirdPartyConfig struct {
	Wechat   WechatConfig   `yaml:"wechat"`
	Dingtalk DingtalkConfig `yaml:"dingtalk"`
	Github   GithubConfig   `yaml:"github"`
	Alipay   AlipayConfig   `yaml:"alipay"`
}

// WechatConfig 微信登录配置
type WechatConfig struct {
	AppId       string `yaml:"appId"`
	AppSecret   string `yaml:"appSecret"`
	RedirectUri string `yaml:"redirectUri"`
}

// DingtalkConfig 钉钉登录配置
type DingtalkConfig struct {
	AppId       string `yaml:"appId"`
	AppSecret   string `yaml:"appSecret"`
	RedirectUri string `yaml:"redirectUri"`
}

// GithubConfig GitHub登录配置
type GithubConfig struct {
	ClientId     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	RedirectUri  string `yaml:"redirectUri"`
}

// AlipayConfig 支付宝登录配置
type AlipayConfig struct {
	AppId       string `yaml:"appId"`
	AppSecret   string `yaml:"appSecret"`
	RedirectUri string `yaml:"redirectUri"`
}

// MailConfig 邮件配置
type MailConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	UseSSL   bool   `yaml:"useSSL"`
}

// SMSConfig 短信配置
type SMSConfig struct {
	Provider  string            `yaml:"provider"`
	APIKey    string            `yaml:"apiKey"`
	SecretKey string            `yaml:"secretKey"`
	SignName  string            `yaml:"signName"`
	Templates map[string]string `yaml:"templates"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`
	Mode string `yaml:"mode"`
}

// DatabaseConfig 数据库配置
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
	// 主从复制配置
	MasterSlaveEnabled bool     `yaml:"masterSlaveEnabled"`
	SlaveHosts         []string `yaml:"slaveHosts"`
	SlavePorts         []int    `yaml:"slavePorts"`
	// 连接池配置
	MaxIdleConns        int `yaml:"maxIdleConns"`
	MaxOpenConns        int `yaml:"maxOpenConns"`
	ConnMaxLifetimeHour int `yaml:"connMaxLifetimeHour"`
}

// MultiActiveConfig 多活部署配置
type MultiActiveConfig struct {
	Enabled             bool   `yaml:"enabled"`
	DataCenterID        string `yaml:"dataCenterID"`
	GlobalLoadBalancing bool   `yaml:"globalLoadBalancing"`
	// Redis跨数据中心同步配置
	RedisSyncEnabled bool   `yaml:"redisSyncEnabled"`
	RedisSyncTarget  string `yaml:"redisSyncTarget"`
	// 数据库跨数据中心同步配置
	DBSyncEnabled bool   `yaml:"dbSyncEnabled"`
	DBSyncTarget  string `yaml:"dbSyncTarget"`
}

// RedisConfig Redis配置
type RedisConfig struct {
	Host            string   `yaml:"host"`
	Port            int      `yaml:"port"`
	Password        string   `yaml:"password"`
	DB              int      `yaml:"db"`
	PoolSize        int      `yaml:"poolSize"`
	ClusterEnabled  bool     `yaml:"clusterEnabled"`
	ClusterAddrs    []string `yaml:"clusterAddrs"`
	SentinelEnabled bool     `yaml:"sentinelEnabled"`
	SentinelMaster  string   `yaml:"sentinelMaster"`
	SentinelAddrs   []string `yaml:"sentinelAddrs"`
}

// JWTConfig JWT配置
type JWTConfig struct {
	Secret                string `yaml:"secret"`
	Issuer                string `yaml:"issuer"`
	AccessTokenExpiry     int    `yaml:"accessTokenExpiry"`
	RefreshTokenExpiry    int    `yaml:"refreshTokenExpiry"`
	PrivateKeyPath        string `yaml:"privateKeyPath"`
	PublicKeyPath         string `yaml:"publicKeyPath"`
	SigningMethod         string `yaml:"signingMethod"`
	MaxConcurrentSessions int    `yaml:"maxConcurrentSessions"` // 最大并发会话数
}



// LoadConfig 加载配置文件
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	globalConfig = &config
	return &config, nil
}

func GetConfig() *Config {
	return globalConfig
}

func InitConfig(config *Config) {
	globalConfig = config
}
