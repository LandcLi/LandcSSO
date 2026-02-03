package third_party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/LandcLi/LandcSSO/service"
)

// -------------------------- GitHub专属Config（内部屏蔽，不对外暴露） --------------------------
type githubConfig struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri  string `json:"redirect_uri"`
}

// -------------------------- GitHub适配器实现 --------------------------
type githubAdapter struct {
	config *githubConfig
}

func (g *githubAdapter) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	// 检查配置
	if g.config == nil || g.config.ClientId == "" {
		return errors.New("GitHub登录配置未设置")
	}

	// 解析redirect_uri
	parsedURI, err := url.Parse(redirectURI)
	if err != nil {
		return errors.New("无效的redirect_uri")
	}

	// 检查是否为http或https协议
	if parsedURI.Scheme != "http" && parsedURI.Scheme != "https" {
		return errors.New("redirect_uri必须使用http或https协议")
	}

	// 检查域名是否与配置中的一致
	// 注意：这里应该与GitHub OAuth应用注册的域名进行比较
	// 实际项目中，应该从配置中读取允许的域名列表进行验证
	if g.config.RedirectUri != "" {
		// 解析配置中的redirect_uri
		configURI, err := url.Parse(g.config.RedirectUri)
		if err == nil && configURI.Host != "" {
			if parsedURI.Host != configURI.Host {
				return errors.New("redirect_uri的域名与配置不一致")
			}
		}
	}

	return nil
}

func (g *githubAdapter) GenerateAuthURL(ctx context.Context, params map[string]string) (string, error) {
	// 检查配置
	if g.config == nil || g.config.ClientId == "" {
		return "", errors.New("GitHub登录配置未设置")
	}

	// 验证redirect_uri
	if err := g.ValidateRedirectURI(ctx, params["redirect_uri"]); err != nil {
		return "", err
	}

	// 构建授权链接
	authURL := "https://github.com/login/oauth/authorize"

	// 对redirect_uri进行URL编码
	encodedRedirectURI := url.QueryEscape(params["redirect_uri"])

	// 设置默认scope
	if params["scope"] == "" {
		params["scope"] = "user:email"
	}

	// 构建参数
	paramsStr := fmt.Sprintf("client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		g.config.ClientId, encodedRedirectURI, params["scope"], params["state"])

	// 添加PKCE参数
	if params["code_challenge"] != "" {
		paramsStr += "&code_challenge=" + url.QueryEscape(params["code_challenge"])
		if params["code_challenge_method"] != "" {
			paramsStr += "&code_challenge_method=" + params["code_challenge_method"]
		} else {
			paramsStr += "&code_challenge_method=S256"
		}
	}

	// 返回完整的授权链接
	return authURL + "?" + paramsStr, nil
}

func (g *githubAdapter) RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error) {
	return "", nil
}

func (g *githubAdapter) FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, error) {
	return "", "", nil
}

// -------------------------- GitHub工厂实现（内部屏蔽Config解析） --------------------------
type githubFactory struct{}

// Type 返回适配器类型，与配置中的key对应
func (f *githubFactory) Type() string {
	return "github"
}

// Create 解析通用配置为GitHub专属Config，创建适配器
// 对外屏蔽Config细节，用户只需传map[string]interface{}
func (f *githubFactory) Create(config map[string]interface{}) (service.ThirdPartyAdapter, error) {
	// 1. 将通用配置转为JSON，再解析为GitHub专属Config（屏蔽解析细节）
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var gcConfig githubConfig
	if err := json.Unmarshal(configBytes, &gcConfig); err != nil {
		return nil, err
	}

	// 2. 校验配置（内部逻辑，不对外暴露）
	if gcConfig.ClientId == "" || gcConfig.ClientSecret == "" {
		return nil, err
	}

	// 3. 创建适配器实例
	return &githubAdapter{config: &gcConfig}, nil
}

// -------------------------- 注册默认工厂（库初始化时自动注册） --------------------------
func init() {
	// 注册GitHub默认工厂，用户可通过RegisterAdapterFactory覆盖
	if _, ok := service.GetFactory("github"); !ok {
		service.RegisterAdapterFactory(&githubFactory{})
	}
}
