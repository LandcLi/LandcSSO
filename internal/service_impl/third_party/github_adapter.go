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
	if err != nil || parsedURI.Host == "" {
		return errors.New("无效的redirect_uri")
	}

	// 协议校验：生产环境强制 HTTPS；仅允许本地开发使用 http 环回地址
	if parsedURI.Scheme == "https" {
		// 允许
	} else if parsedURI.Scheme == "http" {
		host := parsedURI.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errors.New("redirect_uri必须使用HTTPS协议")
		}
	} else {
		return errors.New("redirect_uri必须使用https协议")
	}

	// 配置了 RedirectUri 时，必须与注册的回调地址完全一致（scheme + host + 路径）
	if g.config.RedirectUri != "" {
		configURI, err := url.Parse(g.config.RedirectUri)
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

	// 构建参数（state 与 scope 做 URL 编码，防止特殊字符破坏授权链接）
	paramsStr := fmt.Sprintf("client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		g.config.ClientId, encodedRedirectURI,
		url.QueryEscape(params["scope"]), url.QueryEscape(params["state"]))

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

// RefreshAccessToken 使用 refresh_token 刷新 GitHub access_token
// （GitHub 新版 OAuth App 支持 expiring tokens：access_token 约 8 小时过期）
func (g *githubAdapter) RefreshAccessToken(ctx context.Context, accessToken, refreshToken string) (string, error) {
	// 检查配置
	if g.config == nil || g.config.ClientId == "" || g.config.ClientSecret == "" {
		return "", errors.New("GitHub登录配置未设置")
	}
	if refreshToken == "" {
		return "", errors.New("缺少GitHub refresh_token")
	}

	fetchURL := "https://github.com/login/oauth/access_token"
	requestBody := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s",
		g.config.ClientId, g.config.ClientSecret, refreshToken)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", fetchURL, strings.NewReader(requestBody))
	if err != nil {
		return "", errors.New("构建GitHub刷新请求失败")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("刷新GitHub令牌失败")
	}
	defer resp.Body.Close()

	var tokenData struct {
		AccessToken           string `json:"access_token"`
		ExpiresIn             int    `json:"expires_in"`
		RefreshToken          string `json:"refresh_token"`
		RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
		Scope                 string `json:"scope"`
		TokenType             string `json:"token_type"`
		Error                 string `json:"error"`
		ErrorDescription      string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return "", errors.New("解析GitHub刷新响应失败")
	}

	if tokenData.Error != "" {
		msg := "GitHub API错误: " + tokenData.Error
		if tokenData.ErrorDescription != "" {
			msg += ": " + tokenData.ErrorDescription
		}
		return "", errors.New(msg)
	}
	if tokenData.AccessToken == "" {
		return "", errors.New("GitHub未返回新的access_token")
	}

	return tokenData.AccessToken, nil
}

func (g *githubAdapter) FetchAccessTokenAndRefreshToken(ctx context.Context, code, redirectURI string) (string, string, string, error) {
	// 检查配置
	if g.config == nil || g.config.ClientId == "" || g.config.ClientSecret == "" {
		return "", "", "", errors.New("GitHub登录配置未设置")
	}

	// 验证redirect_uri
	if err := g.ValidateRedirectURI(ctx, redirectURI); err != nil {
		return "", "", "", err
	}

	fetchURL := "https://github.com/login/oauth/access_token"
	requestBody := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s&redirect_uri=%s",
		g.config.ClientId, g.config.ClientSecret, code, redirectURI)

	// 使用 Accept: application/json 获取 JSON 响应（GitHub 默认返回 form 格式）
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", fetchURL, strings.NewReader(requestBody))
	if err != nil {
		return "", "", "", errors.New("构建GitHub令牌请求失败")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", errors.New("获取GitHub令牌失败")
	}
	defer resp.Body.Close()

	var tokenData struct {
		AccessToken           string `json:"access_token"`
		ExpiresIn             int    `json:"expires_in"`
		RefreshToken          string `json:"refresh_token"`
		RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
		Scope                 string `json:"scope"`
		TokenType             string `json:"token_type"`
		Error                 string `json:"error"`
		ErrorDescription      string `json:"error_description"`
		ErrorURI              string `json:"error_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		return "", "", "", errors.New("解析GitHub令牌响应失败")
	}

	// 透出 GitHub 的错误描述
	if tokenData.Error != "" {
		msg := "GitHub API错误: " + tokenData.Error
		if tokenData.ErrorDescription != "" {
			msg += ": " + tokenData.ErrorDescription
		}
		return "", "", "", errors.New(msg)
	}
	if tokenData.AccessToken == "" {
		return "", "", "", errors.New("GitHub未返回access_token")
	}

	// 获取用户信息作为 openId
	// TODO: 按需求文档分工，token换用户信息应由 LandcUserManager 承担；
	//  当前 LandcUserManager 登录仍依赖 openId 作为标识，暂时保留此调用
	userInfoURL := "https://api.github.com/user"
	userReq, _ := http.NewRequest("GET", userInfoURL, nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userReq.Header.Set("Accept", "application/json")

	userClient := &http.Client{Timeout: 10 * time.Second}
	userResp, err := userClient.Do(userReq)
	if err != nil {
		return "", "", "", errors.New("获取GitHub用户信息失败")
	}
	defer userResp.Body.Close()

	var userInfo struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		return "", "", "", errors.New("解析GitHub用户信息失败")
	}

	// 返回 access_token、refresh_token（新版 GitHub OAuth App 支持）和 openId（使用用户ID）
	return tokenData.AccessToken, tokenData.RefreshToken, fmt.Sprintf("%d", userInfo.ID), nil
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
