package sdk

import (
	"bytes"
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

// ThirdPartyLogin 第三方登录
func (c *Client) ThirdPartyLogin(req *ThirdPartyLoginRequest) (*TokenResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data, err := json.Marshal(req)
	if err != nil {
		logger.Errorf(ctx, "序列化第三方登录请求失败: %v", err)
		return nil, err
	}

	// 创建请求
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/user/third-party-login", c.config.Issuer), bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf(ctx, "创建第三方登录请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("X-Client-ID", c.config.ClientID)

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Errorf(ctx, "第三方登录请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "第三方登录失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("第三方登录失败")
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Errorf(ctx, "解析第三方登录响应失败: %v", err)
		return nil, err
	}

	return &tokenResp, nil
}

// BiometricLogin 生物识别登录
func (c *Client) BiometricLogin(req *BiometricLoginRequest) (*TokenResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data, err := json.Marshal(req)
	if err != nil {
		logger.Errorf(ctx, "序列化生物识别登录请求失败: %v", err)
		return nil, err
	}

	// 创建请求
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/user/biometric-login", c.config.Issuer), bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf(ctx, "创建生物识别登录请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("X-Client-ID", c.config.ClientID)

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Errorf(ctx, "生物识别登录请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "生物识别登录失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("生物识别登录失败")
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Errorf(ctx, "解析生物识别登录响应失败: %v", err)
		return nil, err
	}

	return &tokenResp, nil
}

// StartScanCodeLogin 开始扫码登录
func (c *Client) StartScanCodeLogin(req *ScanCodeLoginRequest) (*ScanCodeLoginResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data, err := json.Marshal(req)
	if err != nil {
		logger.Errorf(ctx, "序列化扫码登录请求失败: %v", err)
		return nil, err
	}

	// 创建请求
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/user/scan-code-login", c.config.Issuer), bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf(ctx, "创建扫码登录请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	httpReq.Header.Add("Content-Type", "application/json")

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Errorf(ctx, "扫码登录请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "扫码登录失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("扫码登录失败")
	}

	// 解析响应
	var scanCodeResp ScanCodeLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanCodeResp); err != nil {
		logger.Errorf(ctx, "解析扫码登录响应失败: %v", err)
		return nil, err
	}

	return &scanCodeResp, nil
}

// VerifyScanCodeLogin 验证扫码登录
func (c *Client) VerifyScanCodeLogin(req *ScanCodeVerifyRequest, accessToken string) error {
	ctx := context.Background()
	// 构建请求体
	data, err := json.Marshal(req)
	if err != nil {
		logger.Errorf(ctx, "序列化扫码验证请求失败: %v", err)
		return err
	}

	// 创建请求
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/user/scan-code-login/verify", c.config.Issuer), bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf(ctx, "创建扫码验证请求失败: %v", err)
		return err
	}

	// 添加请求头
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Errorf(ctx, "扫码验证请求失败: %v", err)
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "扫码验证失败，状态码: %d", resp.StatusCode)
		return errors.New("扫码验证失败")
	}

	return nil
}

// CheckScanCodeStatus 检查扫码登录状态
func (c *Client) CheckScanCodeStatus(req *ScanCodeStatusRequest) (*ScanCodeStatusResponse, error) {
	ctx := context.Background()
	// 创建请求
	httpReq, err := http.NewRequest("GET", fmt.Sprintf("%s/user/scan-code-login/status", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建扫码状态请求失败: %v", err)
		return nil, err
	}

	// 添加查询参数
	query := httpReq.URL.Query()
	query.Add("code", req.Code)
	httpReq.URL.RawQuery = query.Encode()

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Errorf(ctx, "扫码状态请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "扫码状态失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("扫码状态失败")
	}

	// 解析响应
	var statusResp ScanCodeStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		logger.Errorf(ctx, "解析扫码状态响应失败: %v", err)
		return nil, err
	}

	return &statusResp, nil
}

// CompleteScanCodeLogin 完成扫码登录
func (c *Client) CompleteScanCodeLogin(req *ScanCodeCompleteRequest, accessToken string) (*TokenResponse, error) {
	ctx := context.Background()
	// 构建请求体
	data, err := json.Marshal(req)
	if err != nil {
		logger.Errorf(ctx, "序列化扫码完成请求失败: %v", err)
		return nil, err
	}

	// 创建请求
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/user/scan-code-login/complete", c.config.Issuer), bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf(ctx, "创建扫码完成请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Errorf(ctx, "扫码完成请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "扫码完成失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("扫码完成失败")
	}

	// 解析响应
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logger.Errorf(ctx, "解析扫码完成响应失败: %v", err)
		return nil, err
	}

	return &tokenResp, nil
}

// GetAuditLogs 获取审计日志
func (c *Client) GetAuditLogs(accessToken string, page, size int, eventType, userID, ip, status string, startTime, endTime string) ([]AuditLogEntry, error) {
	ctx := context.Background()
	// 创建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/audit/list", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建审计日志请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// 添加查询参数
	query := req.URL.Query()
	query.Add("page", fmt.Sprintf("%d", page))
	query.Add("size", fmt.Sprintf("%d", size))
	if eventType != "" {
		query.Add("event_type", eventType)
	}
	if userID != "" {
		query.Add("user_id", userID)
	}
	if ip != "" {
		query.Add("ip", ip)
	}
	if status != "" {
		query.Add("status", status)
	}
	if startTime != "" {
		query.Add("start_time", startTime)
	}
	if endTime != "" {
		query.Add("end_time", endTime)
	}
	req.URL.RawQuery = query.Encode()

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取审计日志请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "获取审计日志失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("获取审计日志失败")
	}

	// 解析响应
	var logs []AuditLogEntry
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		logger.Errorf(ctx, "解析审计日志响应失败: %v", err)
		return nil, err
	}

	return logs, nil
}

// GetSystemStatus 获取系统状态
func (c *Client) GetSystemStatus(accessToken string) (*SystemStatusResponse, error) {
	ctx := context.Background()
	// 创建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/monitor/system/status", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建系统状态请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取系统状态请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "获取系统状态失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("获取系统状态失败")
	}

	// 解析响应
	var statusResp SystemStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		logger.Errorf(ctx, "解析系统状态响应失败: %v", err)
		return nil, err
	}

	return &statusResp, nil
}

// GetAuthMetrics 获取认证指标
func (c *Client) GetAuthMetrics(accessToken string) ([]MetricEntry, error) {
	ctx := context.Background()
	// 创建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/monitor/auth/metrics", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建认证指标请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取认证指标请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "获取认证指标失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("获取认证指标失败")
	}

	// 解析响应
	var metrics []MetricEntry
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		logger.Errorf(ctx, "解析认证指标响应失败: %v", err)
		return nil, err
	}

	return metrics, nil
}

// GetTokenMetrics 获取令牌指标
func (c *Client) GetTokenMetrics(accessToken string) ([]MetricEntry, error) {
	ctx := context.Background()
	// 创建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/monitor/token/metrics", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建令牌指标请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取令牌指标请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "获取令牌指标失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("获取令牌指标失败")
	}

	// 解析响应
	var metrics []MetricEntry
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		logger.Errorf(ctx, "解析令牌指标响应失败: %v", err)
		return nil, err
	}

	return metrics, nil
}

// GetAnomalyEvents 获取异常事件
func (c *Client) GetAnomalyEvents(accessToken string, severity string) ([]AnomalyEvent, error) {
	ctx := context.Background()
	// 创建请求
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/monitor/anomaly/events", c.config.Issuer), nil)
	if err != nil {
		logger.Errorf(ctx, "创建异常事件请求失败: %v", err)
		return nil, err
	}

	// 添加请求头
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// 添加查询参数
	query := req.URL.Query()
	if severity != "" {
		query.Add("severity", severity)
	}
	req.URL.RawQuery = query.Encode()

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取异常事件请求失败: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "获取异常事件失败，状态码: %d", resp.StatusCode)
		return nil, errors.New("获取异常事件失败")
	}

	// 解析响应
	var events []AnomalyEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		logger.Errorf(ctx, "解析异常事件响应失败: %v", err)
		return nil, err
	}

	return events, nil
}
