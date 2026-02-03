package third_party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/LandcLi/LandcSSO/service"
)

// -------------------------- 支付宝专属Config（内部屏蔽，不对外暴露） --------------------------
type alipayConfig struct {
	AppId       string `json:"app_id"`
	AppSecret   string `json:"app_secret"`
	RedirectUri string `json:"redirect_uri"`
}

// -------------------------- 支付宝适配器实现 --------------------------
type alipayAdapter struct {
	config *alipayConfig
}

func (a *alipayAdapter) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	// 检查配置
	if a.config == nil || a.config.AppId == "" {
		return errors.New("支付宝登录配置未设置")
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
	// 注意：这里应该与支付宝开放平台审核通过的域名进行比较
	// 实际项目中，应该从配置中读取允许的域名列表进行验证
	if a.config.RedirectUri != "" {
		// 解析配置中的redirect_uri
		configURI, err := url.Parse(a.config.RedirectUri)
		if err == nil && configURI.Host != "" {
			if parsedURI.Host != configURI.Host {
				return errors.New("redirect_uri的域名与配置不一致")
			}
		}
	}

	return nil
}

func (a *alipayAdapter) GenerateAuthURL(ctx context.Context, params map[string]string) (string, error) {
	// 检查配置
	if a.config == nil || a.config.AppId == "" {
		return "", errors.New("支付宝登录配置未设置")
	}

	// 验证redirect_uri
	if err := a.ValidateRedirectURI(ctx, params["redirect_uri"]); err != nil {
		return "", err
	}

	// 构建授权链接
	authURL := "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"

	// 对redirect_uri进行URL编码
	encodedRedirectURI := url.QueryEscape(params["redirect_uri"])

	// 构建参数
	authParams := fmt.Sprintf("app_id=%s&redirect_uri=%s&scope=auth_user&state=%s",
		a.config.AppId, encodedRedirectURI, params["state"])

	// 返回完整的授权链接
	return authURL + "?" + authParams, nil
}

func (a *alipayAdapter) RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error) {
	return "", nil
}

func (a *alipayAdapter) FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, error) {
	return "", "", nil
}

// -------------------------- 支付宝工厂实现（内部屏蔽Config解析） --------------------------
type alipayFactory struct{}

// Type 返回适配器类型，与配置中的key对应
func (f *alipayFactory) Type() string {
	return "alipay"
}

// Create 解析通用配置为支付宝专属Config，创建适配器
// 对外屏蔽Config细节，用户只需传map[string]interface{}
func (f *alipayFactory) Create(config map[string]interface{}) (service.ThirdPartyAdapter, error) {
	// 1. 将通用配置转为JSON，再解析为支付宝专属Config（屏蔽解析细节）
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var acConfig alipayConfig
	if err := json.Unmarshal(configBytes, &acConfig); err != nil {
		return nil, err
	}

	// 2. 校验配置（内部逻辑，不对外暴露）
	if acConfig.AppId == "" || acConfig.AppSecret == "" {
		return nil, err
	}

	// 3. 创建适配器实例
	return &alipayAdapter{config: &acConfig}, nil
}

// -------------------------- 注册默认工厂（库初始化时自动注册） --------------------------
func init() {
	// 注册支付宝默认工厂，用户可通过RegisterAdapterFactory覆盖
	if _, ok := service.GetFactory("alipay"); !ok {
		service.RegisterAdapterFactory(&alipayFactory{})
	}
}
