package third_party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	if err != nil || parsedURI.Host == "" {
		return errors.New("无效的redirect_uri")
	}

	// 协议校验：生产环境强制 HTTPS；仅允许本地开发使用 http 环回地址。
	// 用 switch 而不是 if-else 链：分支是「按 scheme 分类」，
	// switch 更能表达意图，也避免 ifElseChain 这类可读性问题。
	switch parsedURI.Scheme {
	case "https":
		// 允许
	case "http":
		host := parsedURI.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errors.New("redirect_uri必须使用HTTPS协议")
		}
	default:
		return errors.New("redirect_uri必须使用https协议")
	}

	// 配置了 RedirectUri 时，必须与注册的回调地址完全一致（scheme + host + 路径）
	if a.config.RedirectUri != "" {
		configURI, err := url.Parse(a.config.RedirectUri)
		if err != nil || configURI.Host == "" {
			return errors.New("配置的redirect_uri无效")
		}
		if parsedURI.Scheme != configURI.Scheme ||
			parsedURI.Host != configURI.Host ||
			parsedURI.Path != configURI.Path {
			return errors.New("redirect_uri与配置的注册地址不一致")
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

	// 构建参数（state 做 URL 编码）
	authParams := fmt.Sprintf("app_id=%s&redirect_uri=%s&scope=auth_user&state=%s",
		a.config.AppId, encodedRedirectURI, url.QueryEscape(params["state"]))

	// 返回完整的授权链接
	return authURL + "?" + authParams, nil
}

func (a *alipayAdapter) RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error) {
	return "", nil
}

func (a *alipayAdapter) FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, string, error) {
	// 检查配置
	if a.config == nil || a.config.AppId == "" || a.config.AppSecret == "" {
		return "", "", "", errors.New("支付宝登录配置未设置")
	}

	// 验证redirect_uri
	if err := a.ValidateRedirectURI(ctx, redirectURI); err != nil {
		return "", "", "", err
	}

	// 构建获取access_token的URL
	fetchURL := "https://openapi.alipay.com/gateway.do"

	// 构建参数
	fetchParams := fmt.Sprintf("app_id=%s&method=alipay.system.oauth2.token&grant_type=authorization_code&code=%s&charset=UTF-8&sign_type=RSA2&timestamp=%s&version=1.0",
		a.config.AppId, code, fmt.Sprintf("%d", time.Now().Unix()))

	// 发送POST请求
	resp, err := http.Post(fetchURL, "application/x-www-form-urlencoded", strings.NewReader(fetchParams))
	if err != nil {
		return "", "", "", errors.New("获取支付宝令牌失败")
	}
	defer resp.Body.Close()

	// 解析响应
	var fetchData struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		UserID       string `json:"user_id"`
		AlipayUserID string `json:"alipay_user_id"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&fetchData); err != nil {
		return "", "", "", errors.New("解析支付宝令牌响应失败")
	}

	if fetchData.Error != "" {
		return "", "", "", errors.New("支付宝API错误: " + fetchData.ErrorDesc)
	}

	// 返回access_token、refresh_token和openId（使用user_id）
	return fetchData.AccessToken, fetchData.RefreshToken, fetchData.AlipayUserID, nil
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
