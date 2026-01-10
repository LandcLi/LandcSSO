package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/LandcLi/LandcSSO/pkg/logger"
)

// Client SDK客户端
type Client struct {
	config     *Config
	httpClient *http.Client
}

// NewClient 创建SDK客户端实例
func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetAuthorizationURL 获取授权URL
func (c *Client) GetAuthorizationURL(state string) string {
	params := url.Values{}
	params.Add("client_id", c.config.ClientID)
	params.Add("redirect_uri", c.config.RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", c.config.Scope)
	params.Add("state", state)

	return fmt.Sprintf("%s/authorize?%s", c.config.Issuer, params.Encode())
}

// ExchangeToken 交换令牌
func (c *Client) ExchangeToken(code string) (*TokenResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data := url.Values{}
	data.Add("grant_type", "authorization_code")
	data.Add("code", code)
	data.Add("client_id", c.config.ClientID)
	data.Add("client_secret", c.config.ClientSecret)
	data.Add("redirect_uri", c.config.RedirectURI)

	// 发送请求
	resp, err := c.httpClient.PostForm(fmt.Sprintf("%s/token", c.config.Issuer), data)
	if err != nil {
		logger.Errorf(ctx, "交换令牌请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "交换令牌失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("交换令牌失败")
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Errorf(ctx, "解析令牌响应失败: %v", err)
		return nil, err
	}

	return &tokenResp, nil
}

// RefreshToken 刷新令牌
func (c *Client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data := url.Values{}
	data.Add("grant_type", "refresh_token")
	data.Add("refresh_token", refreshToken)
	data.Add("client_id", c.config.ClientID)
	data.Add("client_secret", c.config.ClientSecret)

	// 发送请求
	resp, err := c.httpClient.PostForm(fmt.Sprintf("%s/token", c.config.Issuer), data)
	if err != nil {
		logger.Errorf(ctx, "刷新令牌请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "刷新令牌失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("刷新令牌失败")
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Errorf(ctx, "解析令牌响应失败: %v", err)
		return nil, err
	}

	return &tokenResp, nil
}

// IntrospectToken 验证令牌
func (c *Client) IntrospectToken(token string) (*IntrospectResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data := url.Values{}
	data.Add("token", token)
	data.Add("client_id", c.config.ClientID)
	data.Add("client_secret", c.config.ClientSecret)

	// 发送请求
	resp, err := c.httpClient.PostForm(fmt.Sprintf("%s/introspect", c.config.Issuer), data)
	if err != nil {
		logger.Errorf(ctx, "验证令牌请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "验证令牌失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("验证令牌失败")
	}

	// 解析响应
	var introspectResp IntrospectResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		logger.Errorf(ctx, "解析验证响应失败: %v", err)
		return nil, err
	}

	return &introspectResp, nil
}

// GetUserInfo 获取用户信息
func (c *Client) GetUserInfo(accessToken string) (*UserInfoResponse, error) {
	ctx := context.Background()
	// 创建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/userinfo", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建用户信息请求失败: %v", err)
		return nil, err
	}

	// 添加Authorization头
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取用户信息请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "获取用户信息失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("获取用户信息失败")
	}

	// 解析响应
	var userInfoResp UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfoResp); err != nil {
		logger.Errorf(ctx, "解析用户信息响应失败: %v", err)
		return nil, err
	}

	return &userInfoResp, nil
}

// Logout 登出
func (c *Client) Logout(accessToken string) error {
	ctx := context.Background()
	// 构建请求体
	data := url.Values{}
	data.Add("token", accessToken)

	// 发送请求
	resp, err := c.httpClient.PostForm(fmt.Sprintf("%s/logout", c.config.Issuer), data)
	if err != nil {
		logger.Errorf(ctx, "登出请求失败: %v", err)
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "登出失败，状态码: %d", resp.StatusCode)
		return errors.New("登出失败")
	}

	return nil
}
