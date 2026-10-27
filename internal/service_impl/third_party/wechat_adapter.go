package third_party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/landc-go/log/facade"
)

// -------------------------- 微信专属Config（内部屏蔽，不对外暴露） --------------------------
type wechatConfig struct {
	AppId       string `json:"app_id"`
	AppSecret   string `json:"app_secret"`
	RedirectUri string `json:"redirect_uri"`
}

// -------------------------- 微信适配器实现 --------------------------
type wechatAdapter struct {
	config *wechatConfig
}

func (w *wechatAdapter) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	// 检查配置
	if w.config == nil || w.config.AppId == "" {
		return errors.New("微信登录配置未设置")
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
	if w.config.RedirectUri != "" {
		configURI, err := url.Parse(w.config.RedirectUri)
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

func (w *wechatAdapter) GenerateAuthURL(ctx context.Context, params map[string]string) (string, error) {
	// 检查配置
	if w.config == nil || w.config.AppId == "" {
		return "", errors.New("微信登录配置未设置")
	}

	// 验证redirect_uri
	if err := w.ValidateRedirectURI(ctx, w.config.RedirectUri); err != nil {
		return "", err
	}

	// 构建授权链接
	authURL := "https://open.weixin.qq.com/connect/qrconnect"

	// 对redirect_uri进行URL编码
	encodedRedirectURI := url.QueryEscape(w.config.RedirectUri)

	// 构建参数（state 做 URL 编码）
	wechatParams := fmt.Sprintf("appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
		w.config.AppId, encodedRedirectURI, url.QueryEscape(params["state"]))

	// 返回完整的授权链接
	return authURL + "?" + wechatParams, nil
}

func (w *wechatAdapter) RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error) {
	// 检查配置
	if w.config == nil || w.config.AppId == "" || w.config.AppSecret == "" {
		return "", errors.New("微信登录配置未设置")
	}

	// 构建刷新token的URL
	refreshURL := "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	refreshParams := fmt.Sprintf("appid=%s&grant_type=refresh_token&refresh_token=%s",
		w.config.AppId, refreshToken)

	// 发送请求
	refreshResp, err := http.Get(refreshURL + "?" + refreshParams)
	if err != nil {
		facade.Errorf("刷新微信access_token失败: %v", err)
		return "", errors.New("刷新微信令牌失败")
	}
	defer refreshResp.Body.Close()

	// 解析响应
	var refreshData struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		OpenID       string `json:"openid"`
		Scope        string `json:"scope"`
		Errcode      int    `json:"errcode"`
		Errmsg       string `json:"errmsg"`
	}

	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshData); err != nil {
		facade.Errorf("解析微信刷新token响应失败: %v", err)
		return "", errors.New("解析微信刷新令牌响应失败")
	}

	if refreshData.Errcode != 0 {
		facade.Errorf("微信API错误: %d, %s", refreshData.Errcode, refreshData.Errmsg)
		return "", errors.New("微信API错误: " + refreshData.Errmsg)
	}

	// 返回新的access_token
	return refreshData.AccessToken, nil
}

func (w *wechatAdapter) FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, string, error) {
	// 检查配置
	if w.config == nil || w.config.AppId == "" || w.config.AppSecret == "" {
		return "", "", "", errors.New("微信登录配置未设置")
	}
	// 验证redirect_uri
	if err := w.ValidateRedirectURI(ctx, redirectURI); err != nil {
		return "", "", "", err
	}
	// 构建获取access_token的URL
	fetchURL := "https://api.weixin.qq.com/sns/oauth2/access_token"
	fetchParams := fmt.Sprintf("appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		w.config.AppId, w.config.AppSecret, code)
	// 发送请求
	fetchResp, err := http.Get(fetchURL + "?" + fetchParams)
	if err != nil {
		facade.Errorf("获取微信access_token失败: %v", err)
		return "", "", "", errors.New("获取微信令牌失败")
	}
	defer fetchResp.Body.Close()
	// 解析响应
	var fetchData struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		OpenID       string `json:"openid"`
		Scope        string `json:"scope"`
		Errcode      int    `json:"errcode"`
		Errmsg       string `json:"errmsg"`
	}
	if err := json.NewDecoder(fetchResp.Body).Decode(&fetchData); err != nil {
		facade.Errorf("解析微信获取token响应失败: %v", err)
		return "", "", "", errors.New("解析微信获取令牌响应失败")
	}
	if fetchData.Errcode != 0 {
		facade.Errorf("微信API错误: %d, %s", fetchData.Errcode, fetchData.Errmsg)
		return "", "", "", errors.New("微信API错误: " + fetchData.Errmsg)
	}
	// 返回access_token、refresh_token和openId
	return fetchData.AccessToken, fetchData.RefreshToken, fetchData.OpenID, nil
}

// -------------------------- 微信工厂实现（内部屏蔽Config解析） --------------------------
type wechatFactory struct{}

// Type 返回适配器类型，与配置中的key对应
func (f *wechatFactory) Type() string {
	return "wechat"
}

// Create 解析通用配置为微信专属Config，创建适配器
// 对外屏蔽Config细节，用户只需传map[string]interface{}
func (f *wechatFactory) Create(config map[string]interface{}) (service.ThirdPartyAdapter, error) {
	// 1. 将通用配置转为JSON，再解析为微信专属Config（屏蔽解析细节）
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var wcConfig wechatConfig
	if err := json.Unmarshal(configBytes, &wcConfig); err != nil {
		return nil, err
	}

	// 2. 校验配置（内部逻辑，不对外暴露）
	if wcConfig.AppId == "" || wcConfig.AppSecret == "" {
		return nil, err
	}

	// 3. 创建适配器实例
	return &wechatAdapter{config: &wcConfig}, nil
}

// -------------------------- 注册默认工厂（库初始化时自动注册） --------------------------
func init() {
	// 注册微信默认工厂，用户可通过RegisterAdapterFactory覆盖
	if _, ok := service.GetFactory("wechat"); !ok {
		service.RegisterAdapterFactory(&wechatFactory{})
	}
}
