package config

import (
	"os"

	framecache "github.com/LandcLi/landc-go/frame/pkg/cache"
	framedb "github.com/LandcLi/landc-go/frame/pkg/db"
	"github.com/LandcLi/landc-go/log/facade"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v2"
	"gorm.io/gorm"
)

var globalConfig *Config

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Database   DatabaseConfig   `yaml:"database"`
	Redis      RedisConfig      `yaml:"redis"`
	JWT        JWTConfig        `yaml:"jwt"`
	Log        facade.LogConfig `yaml:"log"`
	Mail       MailConfig       `yaml:"mail"`
	SMS        SMSConfig        `yaml:"sms"`
	ThirdParty ThirdPartyConfig `yaml:"thirdParty"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`
	Mode string `yaml:"mode"`
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

type ThirdPartyConfig struct {
	Wechat   WechatConfig   `yaml:"wechat"`
	Dingtalk DingtalkConfig `yaml:"dingtalk"`
	Github   GithubConfig   `yaml:"github"`
	Alipay   AlipayConfig   `yaml:"alipay"`
}

type WechatConfig struct {
	AppId       string `yaml:"appId"`
	AppSecret   string `yaml:"appSecret"`
	RedirectUri string `yaml:"redirectUri"`
}

type DingtalkConfig struct {
	AppId       string `yaml:"appId"`
	AppSecret   string `yaml:"appSecret"`
	RedirectUri string `yaml:"redirectUri"`
}

type GithubConfig struct {
	ClientId     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	RedirectUri  string `yaml:"redirectUri"`
}

type AlipayConfig struct {
	AppId       string `yaml:"appId"`
	AppSecret   string `yaml:"appSecret"`
	RedirectUri string `yaml:"redirectUri"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	globalConfig = &cfg
	return &cfg, nil
}

func GetConfig() *Config {
	if globalConfig == nil {
		cfg, err := LoadConfig("config.yaml")
		if err == nil {
			globalConfig = cfg
		} else {
			panic("load config failed: " + err.Error())
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
	return framecache.GetRedis()
}
