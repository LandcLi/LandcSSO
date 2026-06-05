package service

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/landc-go/log/facade"

	"github.com/redis/go-redis/v9"
	"github.com/golang-jwt/jwt/v5"
)

func init() {
	if service.GetAuthService() == nil {
		service.RegisterAuthService(NewAuthServiceImpl())
	}
}

// authServiceImpl 认证服务
type authServiceImpl struct {
	config     *config.Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewAuthService 创建认证服务实例
func NewAuthServiceImpl() *authServiceImpl {
	// Go 1.20+ 不需要手动初始化随机数种子
	// 系统会自动初始化

	service := &authServiceImpl{
		config: config.GetConfig(),
	}

	// 加载RSA密钥（如果配置了）
	if service.config.JWT.PrivateKeyPath != "" && service.config.JWT.PublicKeyPath != "" {
		privateKey, err := os.ReadFile(service.config.JWT.PrivateKeyPath)
		if err != nil {
			facade.Errorf("读取私钥文件失败: %v", err)
		} else {
			privateKeyObj, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
			if err != nil {
				facade.Errorf("解析私钥失败: %v", err)
			} else {
				service.privateKey = privateKeyObj
			}
		}

		publicKey, err := os.ReadFile(service.config.JWT.PublicKeyPath)
		if err != nil {
			facade.Errorf("读取公钥文件失败: %v", err)
		} else {
			publicKeyObj, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
			if err != nil {
				facade.Errorf("解析公钥失败: %v", err)
			} else {
				service.publicKey = publicKeyObj
			}
		}
	}

	return service
}

// Login 用户登录
func (s *authServiceImpl) Login(ctx context.Context, userID uint, differentLocation bool, isNewDevice bool, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 检查是否需要生成临时token
	if differentLocation || isNewDevice {
		// 生成临时token
		return s.generateTempToken(ctx, userID, ip, deviceFingerprint, userAgent)
	}

	// 生成正常令牌
	return s.generateTokens(ctx, userID, "", ip, deviceFingerprint)
}

// generateTempToken 生成临时token
func (s *authServiceImpl) generateTempToken(ctx context.Context, userID uint, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {

	// 设置临时token过期时间为30分钟
	expirationTime := time.Now().Add(30 * time.Minute)

	// 创建声明
	claims := jwt.MapClaims{
		"user_id":            userID,
		"exp":                expirationTime.Unix(),
		"iat":                time.Now().Unix(),
		"iss":                s.config.JWT.Issuer,
		"scope":              "temp",
		"ip":                 ip,
		"device_fingerprint": deviceFingerprint,
		"type":               "temp",
	}

	// 生成临时token
	var token *jwt.Token
	var tokenString string
	var err error

	if s.config.JWT.SigningMethod == "RS256" && s.privateKey != nil {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = token.SignedString(s.privateKey)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString([]byte(s.config.JWT.Secret))
	}

	if err != nil {
		return nil, errors.New("临时令牌生成失败")
	}

	// 存储临时token信息到Redis，以便后续验证
	if config.GetRedis() != nil {
		tempTokenKey := fmt.Sprintf("temp_token:%s", tokenString)
		tempTokenData := map[string]interface{}{
			"user_id":            userID,
			"ip":                 ip,
			"device_fingerprint": deviceFingerprint,
			"created_at":         time.Now().Unix(),
		}
		tempTokenJSON, _ := json.Marshal(tempTokenData)
		config.GetRedis().Set(ctx, tempTokenKey, tempTokenJSON, 30*time.Minute)
	}

	return &model.TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    1800, // 30分钟
		RefreshToken: "",
		IsTmp:        true,
	}, nil
}

// ExchangeTempToken 兑换临时token为正式token
func (s *authServiceImpl) ExchangeTempToken(ctx context.Context, tempToken string, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {

	// 验证临时token
	if config.GetRedis() == nil {
		return nil, errors.New("Redis未初始化")
	}

	tempTokenKey := fmt.Sprintf("temp_token:%s", tempToken)
	tempTokenDataJSON, err := config.GetRedis().Get(ctx, tempTokenKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("临时令牌不存在或已过期")
		}
		return nil, errors.New("验证临时令牌失败")
	}

	// 解析临时token数据
	var tempTokenData map[string]interface{}
	if err := json.Unmarshal(tempTokenDataJSON, &tempTokenData); err != nil {
		return nil, errors.New("解析临时令牌数据失败")
	}

	userID, ok := tempTokenData["user_id"].(float64)
	if !ok {
		return nil, errors.New("无效的用户ID")
	}

	// 删除临时token
	config.GetRedis().Del(ctx, tempTokenKey)

	// 生成正式令牌
	return s.generateTokens(ctx, uint(userID), "", ip, deviceFingerprint)
}

// generateTokens 生成令牌
func (s *authServiceImpl) generateTokens(ctx context.Context, userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	// 检查config是否为nil
	if s.config == nil {
		return nil, errors.New("配置未初始化")
	}

	// 检查并发会话数限制
	if s.config.JWT.MaxConcurrentSessions > 0 {
		err := s.checkConcurrentSessions(userID)
		if err != nil {
			return nil, err
		}
	}

	// 生成访问令牌
	accessToken, expiresIn, err := s.generateAccessToken(userID, clientID, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	// 生成刷新令牌
	refreshToken, refreshExpiresIn, err := s.generateRefreshToken(userID, clientID)
	if err != nil {
		return nil, err
	}

	// 保存令牌
	token := &model.Token{
		UserID:            userID,
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		ExpiresAt:         time.Now().Add(time.Duration(expiresIn) * time.Second),
		RefreshExpiresAt:  time.Now().Add(time.Duration(refreshExpiresIn) * time.Second),
		ClientID:          clientID,
		Scope:             "openid profile email",
		Revoked:           false,
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
	}

	_, err = dao.GetTokenDao().Create(token)
	if err != nil {
		return nil, errors.New("令牌保存失败")
	}

	return &model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        "openid profile email",
		IsTmp:        false,
	}, nil
}

// checkConcurrentSessions 检查并发会话数限制
func (s *authServiceImpl) checkConcurrentSessions(userID uint) error {

	// 获取用户的所有有效令牌
	tokens, err := dao.GetTokenDao().FindByUserID(userID)
	if err != nil {
		return nil
	}

	// 过滤出有效的令牌（未撤销且未过期）
	var validTokens []*model.Token
	now := time.Now()
	for _, token := range tokens {
		if !token.Revoked && token.ExpiresAt.After(now) {
			validTokens = append(validTokens, token)
		}
	}

	// 检查会话数是否超过限制
	if len(validTokens) >= s.config.JWT.MaxConcurrentSessions {
		// 超过限制，踢掉最旧的会话
		// 按创建时间排序，找到最旧的令牌
		var oldestToken *model.Token
		for _, token := range validTokens {
			if oldestToken == nil || token.CreatedAt.Before(oldestToken.CreatedAt) {
				oldestToken = token
			}
		}

		// 撤销最旧的令牌
		if oldestToken != nil {
			oldestToken.Revoked = true
			_, err := dao.GetTokenDao().Update(oldestToken)
			if err != nil {
				facade.Errorf("撤销旧令牌失败: %v", err)
			}
		}
	}

	return nil
}

// generateAccessToken 生成访问令牌
func (s *authServiceImpl) generateAccessToken(userID uint, clientID string, ip string, deviceFingerprint string) (string, int, error) {
	// 检查config是否为nil
	if s.config == nil {
		return "", 0, errors.New("配置未初始化")
	}

	// 设置过期时间
	expiresIn := s.config.JWT.AccessTokenExpiry
	expirationTime := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// 创建声明
	claims := jwt.MapClaims{
		"user_id":            userID,
		"exp":                expirationTime.Unix(),
		"iat":                time.Now().Unix(),
		"iss":                s.config.JWT.Issuer,
		"client_id":          clientID,
		"scope":              "openid profile email",
		"ip":                 ip,
		"device_fingerprint": deviceFingerprint,
	}

	// 根据配置和可用的密钥选择签名方法
	var token *jwt.Token
	var tokenString string
	var err error

	if s.config.JWT.SigningMethod == "RS256" && s.privateKey != nil {
		// 使用RS256算法
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = token.SignedString(s.privateKey)
	} else {
		// 使用默认的HS256算法
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString([]byte(s.config.JWT.Secret))
	}

	if err != nil {
		return "", 0, errors.New("令牌生成失败")
	}

	return tokenString, expiresIn, nil
}

// generateRefreshToken 生成刷新令牌
func (s *authServiceImpl) generateRefreshToken(userID uint, clientID string) (string, int, error) {
	// 检查config是否为nil
	if s.config == nil {
		return "", 0, errors.New("配置未初始化")
	}

	// 设置过期时间
	expiresIn := s.config.JWT.RefreshTokenExpiry
	expirationTime := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// 创建声明
	claims := jwt.MapClaims{
		"user_id":   userID,
		"exp":       expirationTime.Unix(),
		"iat":       time.Now().Unix(),
		"iss":       s.config.JWT.Issuer,
		"client_id": clientID,
		"type":      "refresh",
	}

	// 根据配置和可用的密钥选择签名方法
	var token *jwt.Token
	var tokenString string
	var err error

	if s.config.JWT.SigningMethod == "RS256" && s.privateKey != nil {
		// 使用RS256算法
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = token.SignedString(s.privateKey)
	} else {
		// 使用默认的HS256算法
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString([]byte(s.config.JWT.Secret))
	}

	if err != nil {
		return "", 0, errors.New("刷新令牌生成失败")
	}

	return tokenString, expiresIn, nil
}

// ValidateToken 验证令牌
func (s *authServiceImpl) ValidateToken(ctx context.Context, tokenString string, ip string, deviceFingerprint string) (*model.Claims, error) {
	// 检查config是否为nil
	if s.config == nil {
		return nil, errors.New("配置未初始化")
	}

	// 解析令牌
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			// 使用HS256算法
			return []byte(s.config.JWT.Secret), nil
		} else if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			// 使用RS256算法
			if s.publicKey != nil {
				return s.publicKey, nil
			}
			return nil, errors.New("缺少公钥")
		}
		return nil, errors.New("无效的令牌签名方法")
	})

	if err != nil {
		return nil, err
	}

	// 验证令牌
	if !token.Valid {
		return nil, errors.New("无效的令牌")
	}

	// 提取声明
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("无效的令牌声明")
	}

	// 转换为自定义声明
	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		return nil, errors.New("无效的用户ID")
	}
	userID := uint(userIDFloat)

	username, ok := claims["username"].(string)
	if !ok {
		username = ""
	}

	email, ok := claims["email"].(string)
	if !ok {
		email = ""
	}

	scope, ok := claims["scope"].(string)
	if !ok {
		scope = ""
	}

	clientID, ok := claims["client_id"].(string)
	if !ok {
		clientID = ""
	}

	// 提取IP和设备指纹
	var tokenIP string
	var tokenDeviceFingerprint string
	if ipClaim, ok := claims["ip"].(string); ok {
		tokenIP = ipClaim
	}
	if deviceClaim, ok := claims["device_fingerprint"].(string); ok {
		tokenDeviceFingerprint = deviceClaim
	}

	// 验证IP和设备指纹（如果存在）
	if tokenIP != "" && ip != "" && tokenIP != ip {
		return nil, errors.New("IP地址不匹配")
	}
	if tokenDeviceFingerprint != "" && deviceFingerprint != "" && tokenDeviceFingerprint != deviceFingerprint {
		return nil, errors.New("设备指纹不匹配")
	}

	return &model.Claims{
		UserID:            userID,
		Username:          username,
		Email:             email,
		Scope:             scope,
		ClientID:          clientID,
		IP:                tokenIP,
		DeviceFingerprint: tokenDeviceFingerprint,
	}, nil
}

// RefreshToken 刷新令牌
func (s *authServiceImpl) RefreshToken(ctx context.Context, refreshToken string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	// 查找刷新令牌
	token, err := dao.GetTokenDao().FindByRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("刷新令牌不存在")
	}

	// 检查令牌是否已撤销
	if token.Revoked {
		return nil, errors.New("刷新令牌已撤销")
	}

	// 检查刷新令牌是否过期
	if time.Now().After(token.RefreshExpiresAt) {
		return nil, errors.New("刷新令牌已过期")
	}

	// 生成新令牌
	newTokens, err := s.generateTokens(ctx, token.UserID, token.ClientID, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	// 撤销旧令牌
	token.Revoked = true
	_, err = dao.GetTokenDao().Update(token)
	if err != nil {
		facade.Errorf("撤销旧令牌失败: %v", err)
	}

	return newTokens, nil
}

// GenerateTokens 生成令牌（公开方法）
func (s *authServiceImpl) GenerateTokens(ctx context.Context, userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	return s.generateTokens(ctx, userID, clientID, ip, deviceFingerprint)
}

// RevokeToken 撤销令牌
func (s *authServiceImpl) RevokeToken(ctx context.Context, tokenString string) error {
	// 查找令牌
	token, err := dao.GetTokenDao().FindByAccessToken(tokenString)
	if err != nil {
		return errors.New("令牌不存在")
	}

	// 撤销令牌
	token.Revoked = true
	_, err = dao.GetTokenDao().Update(token)
	if err != nil {
		return errors.New("令牌撤销失败")
	}

	return nil
}

// Logout 用户登出
func (s *authServiceImpl) Logout(ctx context.Context, userID uint, ip string, deviceFingerprint string, userAgent string) error {
	// 1. 撤销用户的所有令牌
	err := s.revokeUserTokens(userID)
	if err != nil {
		// 令牌撤销失败不影响登出流程
	}

	// 2. 清理用户的所有会话
	err = service.GetSessionService().DeleteUserSessions(userID)
	if err != nil {
		// 会话清理失败不影响登出流程
	}

	// 3. 通知所有已登录的应用
	err = s.notifyClients(userID)
	if err != nil {
		// 通知失败不影响登出流程
	}

	return nil
}

// revokeUserTokens 撤销用户的所有令牌
func (s *authServiceImpl) revokeUserTokens(userID uint) error {
	// 撤销用户的所有令牌
	return dao.GetTokenDao().RevokeByUserID(userID)
}

// notifyClients 通知所有已登录的应用
func (s *authServiceImpl) notifyClients(userID uint) error {

	// 1. 查询用户的所有活跃令牌
	tokens, err := dao.GetTokenDao().FindByUserID(userID)
	if err != nil {
		facade.Errorf("查询用户活跃令牌失败: %v", err)
		return err
	}

	// 2. 提取并去重客户端ID
	clientIDs := make(map[string]bool)
	for _, token := range tokens {
		if token.ClientID != "" {
			clientIDs[token.ClientID] = true
		}
	}

	// 3. 向每个客户端应用发送登出通知
	for clientID := range clientIDs {
		// 获取客户端信息
		client, err := service.GetClientService().GetByClientID(clientID)
		if err != nil {
			facade.Errorf("获取客户端信息失败: %v", err)
			continue
		}

		// 解析重定向URI
		var redirectURIs []string
		if client.RedirectURIs != "" {
			json.Unmarshal([]byte(client.RedirectURIs), &redirectURIs)
		}

		// 向每个重定向URI发送登出通知
		for _, redirectURI := range redirectURIs {
			// 构建登出通知URL
			logoutURL := fmt.Sprintf("%s?logout=1&client_id=%s", redirectURI, clientID)

			// 发送HTTP请求通知登出
			s.sendLogoutNotification(logoutURL)
		}
	}

	return nil
}

// sendLogoutNotification 发送登出通知
func (s *authServiceImpl) sendLogoutNotification(url string) {

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 发送GET请求
	resp, err := client.Get(url)
	if err != nil {
		facade.Errorf("发送登出通知失败: %v, URL: %s", err, url)
		return
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		facade.Errorf("登出通知响应失败: %s, URL: %s", resp.Status, url)
		return
	}

	facade.Infof("登出通知发送成功: %s", url)
}

// GenerateAuthorizationCode 生成授权码
func (s *authServiceImpl) GenerateAuthorizationCode(ctx context.Context, userID uint, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) (string, error) {
	// 生成32位随机授权码
	code := generateRandomString(32)

	// 创建授权码记录
	authCode := &model.AuthorizationCode{
		Code:                code,
		UserID:              userID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute), // 授权码10分钟过期
		Used:                false,
	}

	// 保存授权码
	_, err := dao.GetTokenDao().CreateAuthorizationCode(authCode)
	if err != nil {
		return "", errors.New("授权码生成失败")
	}

	return code, nil
}

// ValidateAuthorizationCode 验证授权码
func (s *authServiceImpl) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*model.AuthorizationCode, error) {
	// 查找授权码
	authCode, err := dao.GetTokenDao().FindByCode(code)
	if err != nil {
		return nil, errors.New("授权码不存在")
	}

	// 检查授权码是否已使用
	if authCode.Used {
		return nil, errors.New("授权码已使用")
	}

	// 检查授权码是否过期
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("授权码已过期")
	}

	// 检查客户端ID是否匹配
	if authCode.ClientID != clientID {
		return nil, errors.New("客户端ID不匹配")
	}

	// 检查重定向URI是否匹配
	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("重定向URI不匹配")
	}

	// PKCE验证
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, errors.New("缺少code_verifier参数")
		}

		// 根据CodeChallengeMethod验证codeVerifier
		var expectedCodeChallenge string
		if authCode.CodeChallengeMethod == "S256" {
			// 使用SHA256哈希
			hash := sha256.Sum256([]byte(codeVerifier))
			expectedCodeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
		} else {
			// 使用plain方法
			expectedCodeChallenge = codeVerifier
		}

		if authCode.CodeChallenge != expectedCodeChallenge {
			return nil, errors.New("code_verifier验证失败")
		}
	}

	// 标记授权码为已使用
	err = dao.GetTokenDao().MarkAsUsed(authCode.ID)
	if err != nil {
		return nil, errors.New("授权码验证失败")
	}

	return authCode, nil
}

// generateRandomString 生成随机字符串
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func (s *authServiceImpl) GetJWKS(ctx context.Context) (*v1.JWKSResponse, error) {
	// 调用认证服务获取JWKS
	return &v1.JWKSResponse{
		Keys: []v1.Key{
			{
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				Kid: "key:1234567890",
				N:   "t6V6zZ7X5c4b3a2s1d0f9g8h7j6k5l4m3n2o1p0",
				E:   "AQAB",
			},
		},
	}, nil
}

// Introspect 令牌验证
func (s *authServiceImpl) Introspect(ctx context.Context, tokenString string, ip string, deviceFingerprint string) (*v1.IntrospectResponse, error) {
	// 验证令牌
	claims, err := s.ValidateToken(ctx, tokenString, ip, deviceFingerprint)
	if err != nil {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	// 查找令牌记录
	token, err := dao.GetTokenDao().FindByAccessToken(tokenString)
	if err != nil {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	// 检查令牌是否已撤销
	if token.Revoked {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	// 检查令牌是否过期
	if time.Now().After(token.ExpiresAt) {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	// 返回令牌验证结果
	return &v1.IntrospectResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		UserID:    claims.UserID,
		Username:  claims.Username,
		TokenType: "Bearer",
		Exp:       token.ExpiresAt.Unix(),
		Iat:       token.CreatedAt.Unix(),
		Nbf:       token.CreatedAt.Unix(),
		Iss:       s.config.JWT.Issuer,
		Sub:       claims.UserID,
		Aud:       claims.ClientID,
	}, nil
}
