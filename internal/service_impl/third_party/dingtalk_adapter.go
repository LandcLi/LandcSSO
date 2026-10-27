package third_party

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/LandcLi/LandcSSO/service"
)

// -------------------------- 钉钉专属Config（内部屏蔽，不对外暴露） --------------------------
type dingtalkConfig struct {
	AppId     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
}

// -------------------------- 钉钉适配器实现 --------------------------
type dingtalkAdapter struct {
	config *dingtalkConfig
}

func (d *dingtalkAdapter) ValidateRedirectURI(ctx context.Context, redirectURI string) error {
	return nil
}

func (d *dingtalkAdapter) GenerateAuthURL(ctx context.Context, params map[string]string) (string, error) {
	return "", nil
}

func (d *dingtalkAdapter) RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error) {
	return "", nil
}

func (d *dingtalkAdapter) FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, string, error) {
	// 检查配置
	if d.config == nil || d.config.AppId == "" || d.config.AppSecret == "" {
		return "", "", "", errors.New("钉钉登录配置未设置")
	}

	// 构建获取access_token的URL
	fetchURL := "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"

	// 构建请求体
	//
	// 用 %q 而不是 "%s"：AppSecret / code 里若出现引号或反斜杠，
	// 手工拼进去的 JSON 会直接损坏（甚至可被构造成注入）。%q 会正确转义并自带引号。
	requestBody := fmt.Sprintf(`{"clientId":%q,"clientSecret":%q,"code":%q,"grantType":"authorization_code"}`,
		d.config.AppId, d.config.AppSecret, code)

	// 发送POST请求
	resp, err := http.Post(fetchURL, "application/json", strings.NewReader(requestBody))
	if err != nil {
		return "", "", "", errors.New("获取钉钉令牌失败")
	}
	defer resp.Body.Close()

	// 解析响应
	var fetchData struct {
		AccessToken  string `json:"accessToken"`
		ExpiresIn    int    `json:"expiresIn"`
		RefreshToken string `json:"refreshToken"`
		OpenID       string `json:"openId"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&fetchData); err != nil {
		return "", "", "", errors.New("解析钉钉令牌响应失败")
	}

	if fetchData.Error != "" {
		return "", "", "", errors.New("钉钉API错误: " + fetchData.ErrorDesc)
	}

	// 返回access_token、refresh_token和openId
	return fetchData.AccessToken, fetchData.RefreshToken, fetchData.OpenID, nil
}

// -------------------------- 钉钉工厂实现（内部屏蔽Config解析） --------------------------
type dingtalkFactory struct{}

// Type 返回适配器类型，与配置中的key对应
func (f *dingtalkFactory) Type() string {
	return "dingtalk"
}

// Create 解析通用配置为钉钉专属Config，创建适配器
// 对外屏蔽Config细节，用户只需传map[string]interface{}
func (f *dingtalkFactory) Create(config map[string]interface{}) (service.ThirdPartyAdapter, error) {
	// 1. 将通用配置转为JSON，再解析为钉钉专属Config（屏蔽解析细节）
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var dcConfig dingtalkConfig
	if err := json.Unmarshal(configBytes, &dcConfig); err != nil {
		return nil, err
	}

	// 2. 校验配置（内部逻辑，不对外暴露）
	if dcConfig.AppId == "" || dcConfig.AppSecret == "" {
		return nil, err
	}

	// 3. 创建适配器实例
	return &dingtalkAdapter{config: &dcConfig}, nil
}

// -------------------------- 注册默认工厂（库初始化时自动注册） --------------------------
func init() {
	// 注册钉钉默认工厂，用户可通过RegisterAdapterFactory覆盖
	if _, ok := service.GetFactory("dingtalk"); !ok {
		service.RegisterAdapterFactory(&dingtalkFactory{})
	}
}
