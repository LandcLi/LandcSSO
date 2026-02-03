package third_party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/logger"
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
	if err != nil {
		return errors.New("无效的redirect_uri")
	}

	// 检查是否为http或https协议
	if parsedURI.Scheme != "http" && parsedURI.Scheme != "https" {
		return errors.New("redirect_uri必须使用http或https协议")
	}

	// 检查域名是否与配置中的一致
	// 注意：这里应该与微信开放平台审核通过的域名进行比较
	// 实际项目中，应该从配置中读取允许的域名列表进行验证
	if w.config.RedirectUri != "" {
		// 解析配置中的redirect_uri
		configURI, err := url.Parse(w.config.RedirectUri)
		if err == nil && configURI.Host != "" {
			if parsedURI.Host != configURI.Host {
				return errors.New("redirect_uri的域名与配置不一致")
			}
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

	// 构建参数
	wechatParams := fmt.Sprintf("appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
		w.config.AppId, encodedRedirectURI, params["state"])

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
		logger.Errorf(ctx, "刷新微信access_token失败: %v", err)
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
		logger.Errorf(ctx, "解析微信刷新token响应失败: %v", err)
		return "", errors.New("解析微信刷新令牌响应失败")
	}

	if refreshData.Errcode != 0 {
		logger.Errorf(ctx, "微信API错误: %d, %s", refreshData.Errcode, refreshData.Errmsg)
		return "", errors.New("微信API错误: " + refreshData.Errmsg)
	}

	// 返回新的access_token
	return refreshData.AccessToken, nil
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
