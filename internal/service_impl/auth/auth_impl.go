package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/security"
	frameauth "github.com/LandcLi/landc-go/frame/pkg/auth"
	"github.com/LandcLi/landc-go/log/facade"
)

func init() {
	if service.GetAuthService() == nil {
		service.RegisterAuthService(NewAuthServiceImpl())
	}
}

type authServiceImpl struct {
	config *config.Config
}

func NewAuthServiceImpl() *authServiceImpl {
	cfg := config.GetConfig()
	if cfg == nil {
		panic("failed to load config")
	}

	return &authServiceImpl{
		config: cfg,
	}
}

// generateAccessToken 生成访问令牌（expiresIn 秒）
func (s *authServiceImpl) generateAccessToken(userID uint, clientID string, ip string, deviceFingerprint string) (string, int, error) {
	expiresIn := s.config.JWT.AccessTokenExpiry
	token, err := frameauth.GenerateTokenWithOpts(userID, "", frameauth.GenerateTokenOption{
		ClientID:          clientID,
		Scope:             "openid profile email",
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		TokenType:         "access",
		ExpireTime:        time.Duration(expiresIn) * time.Second,
	})
	if err != nil {
		return "", 0, errors.New("令牌生成失败")
	}
	return token, expiresIn, nil
}

// generateRefreshToken 生成刷新令牌
func (s *authServiceImpl) generateRefreshToken(userID uint, clientID string) (string, int, error) {
	expiresIn := s.config.JWT.RefreshTokenExpiry
	token, err := frameauth.GenerateTokenWithOpts(userID, "", frameauth.GenerateTokenOption{
		ClientID:  clientID,
		TokenType: "refresh",
		ExpireTime: time.Duration(expiresIn) * time.Second,
	})
	if err != nil {
		return "", 0, errors.New("刷新令牌生成失败")
	}
	return token, expiresIn, nil
}

// generateTempToken 生成临时token
func (s *authServiceImpl) generateTempToken(ctx context.Context, userID uint, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	tokenString, err := frameauth.GenerateTokenWithOpts(userID, "", frameauth.GenerateTokenOption{
		Scope:             "temp",
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		TokenType:         "temp",
		ExpireTime:        30 * time.Minute,
	})
	if err != nil {
		return nil, errors.New("临时令牌生成失败")
	}

	// 存储临时token信息到Redis（可选），以便后续验证
	rc := config.GetRedis()
	if rc != nil {
		tempTokenKey := fmt.Sprintf("temp_token:%s", tokenString)
		tempTokenData := map[string]interface{}{
			"user_id":            userID,
			"ip":                 ip,
			"device_fingerprint": deviceFingerprint,
			"created_at":         time.Now().Unix(),
		}
		tempTokenJSON, _ := json.Marshal(tempTokenData)
		rc.Set(ctx, tempTokenKey, tempTokenJSON, 30*time.Minute)
	}

	return &model.TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    1800,
		RefreshToken: "",
		IsTmp:        true,
	}, nil
}

func (s *authServiceImpl) Login(ctx context.Context, userID uint, differentLocation bool, isNewDevice bool, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	if differentLocation || isNewDevice {
		return s.generateTempToken(ctx, userID, ip, deviceFingerprint, userAgent)
	}
	return s.generateTokens(ctx, userID, "", ip, deviceFingerprint)
}

// generateTokens 生成令牌
func (s *authServiceImpl) generateTokens(ctx context.Context, userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	if s.config == nil {
		return nil, errors.New("配置未初始化")
	}

	if s.config.JWT.MaxConcurrentSessions > 0 {
		if err := s.checkConcurrentSessions(userID); err != nil {
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

func (s *authServiceImpl) checkConcurrentSessions(userID uint) error {
	tokens, err := dao.GetTokenDao().FindByUserID(userID)
	if err != nil {
		return nil
	}

	var validTokens []*model.Token
	now := time.Now()
	for _, token := range tokens {
		if !token.Revoked && token.ExpiresAt.After(now) {
			validTokens = append(validTokens, token)
		}
	}

	if len(validTokens) >= s.config.JWT.MaxConcurrentSessions {
		var oldestToken *model.Token
		for _, token := range validTokens {
			if oldestToken == nil || token.CreatedAt.Before(oldestToken.CreatedAt) {
				oldestToken = token
			}
		}
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

func (s *authServiceImpl) ValidateToken(ctx context.Context, tokenString string, ip string, deviceFingerprint string) (*model.Claims, error) {
	claims, err := frameauth.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.IP != "" && ip != "" && claims.IP != ip {
		return nil, errors.New("IP地址不匹配")
	}
	if claims.DeviceFingerprint != "" && deviceFingerprint != "" && claims.DeviceFingerprint != deviceFingerprint {
		return nil, errors.New("设备指纹不匹配")
	}

	return &model.Claims{
		UserID:            claims.UserID,
		Username:          claims.Username,
		Scope:             claims.Scope,
		ClientID:          claims.ClientID,
		IP:                claims.IP,
		DeviceFingerprint: claims.DeviceFingerprint,
		// 注意：JWT 中未携带 email claim，这里不再错误地使用 username 填充 email。
		// OIDC userinfo 端点应通过用户服务获取真实 email（见 docs/api.md）。
		Email: "",
	}, nil
}

func (s *authServiceImpl) ExchangeTempToken(ctx context.Context, tempToken string, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 优先从Redis验证（如果可用）
	rc := config.GetRedis()
	if rc != nil {
		tempTokenKey := fmt.Sprintf("temp_token:%s", tempToken)
		tempTokenDataJSON, err := rc.Get(ctx, tempTokenKey).Bytes()
		if err == nil {
			var tempTokenData map[string]interface{}
			if err := json.Unmarshal(tempTokenDataJSON, &tempTokenData); err == nil {
				if userID, ok := tempTokenData["user_id"].(float64); ok {
					rc.Del(ctx, tempTokenKey)
					return s.generateTokens(ctx, uint(userID), "", ip, deviceFingerprint)
				}
			}
		}
	}

	// Redis不可用或验证失败时，直接验证JWT获取用户ID
	claims, err := frameauth.ParseToken(tempToken)
	if err != nil {
		return nil, errors.New("临时令牌不存在或已过期")
	}

	return s.generateTokens(ctx, claims.UserID, "", ip, deviceFingerprint)
}

func (s *authServiceImpl) RefreshToken(ctx context.Context, refreshToken string, clientID string, clientSecret string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	token, err := dao.GetTokenDao().FindByRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("刷新令牌不存在")
	}

	if token.Revoked {
		return nil, errors.New("刷新令牌已撤销")
	}

	if time.Now().After(token.RefreshExpiresAt) {
		return nil, errors.New("刷新令牌已过期")
	}

	// RFC 6749 §6：刷新令牌必须进行客户端认证，且调用方客户端必须与令牌绑定客户端一致
	if err := s.verifyClient(clientID, clientSecret); err != nil {
		return nil, err
	}
	if token.ClientID != "" && token.ClientID != clientID {
		return nil, errors.New("客户端与刷新令牌不匹配")
	}

	newTokens, err := s.generateTokens(ctx, token.UserID, token.ClientID, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	token.Revoked = true
	_, err = dao.GetTokenDao().Update(token)
	if err != nil {
		facade.Errorf("撤销旧令牌失败: %v", err)
	}

	return newTokens, nil
}

// verifyClient 校验客户端凭证（client_id + client_secret），使用恒定时间比较
func (s *authServiceImpl) verifyClient(clientID, clientSecret string) error {
	if clientID == "" {
		return errors.New("缺少客户端认证信息")
	}
	client, err := service.GetClientService().GetByClientID(clientID)
	if err != nil {
		return errors.New("客户端不存在")
	}
	if client.Status != 1 {
		return errors.New("客户端已被禁用")
	}
	if !security.VerifySecret(client.ClientSecret, clientSecret) {
		return errors.New("客户端认证失败")
	}
	return nil
}

func (s *authServiceImpl) GenerateTokens(ctx context.Context, userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	return s.generateTokens(ctx, userID, clientID, ip, deviceFingerprint)
}

func (s *authServiceImpl) RevokeToken(ctx context.Context, tokenString string) error {
	token, err := dao.GetTokenDao().FindByAccessToken(tokenString)
	if err != nil {
		return errors.New("令牌不存在")
	}

	token.Revoked = true
	_, err = dao.GetTokenDao().Update(token)
	if err != nil {
		return errors.New("令牌撤销失败")
	}
	return nil
}

func (s *authServiceImpl) Logout(ctx context.Context, userID uint, ip string, deviceFingerprint string, userAgent string) error {
	_ = s.revokeUserTokens(userID)

	_ = service.GetSessionService().DeleteUserSessions(userID)

	_ = s.notifyClients(userID)

	return nil
}

func (s *authServiceImpl) revokeUserTokens(userID uint) error {
	return dao.GetTokenDao().RevokeByUserID(userID)
}

func (s *authServiceImpl) notifyClients(userID uint) error {
	tokens, err := dao.GetTokenDao().FindByUserID(userID)
	if err != nil {
		facade.Errorf("查询用户活跃令牌失败: %v", err)
		return err
	}

	clientIDs := make(map[string]bool)
	for _, token := range tokens {
		if token.ClientID != "" {
			clientIDs[token.ClientID] = true
		}
	}

	for clientID := range clientIDs {
		client, err := service.GetClientService().GetByClientID(clientID)
		if err != nil {
			facade.Errorf("获取客户端信息失败: %v", err)
			continue
		}

		var redirectURIs []string
		if client.RedirectURIs != "" {
			json.Unmarshal([]byte(client.RedirectURIs), &redirectURIs)
		}

		for _, redirectURI := range redirectURIs {
			logoutURL := fmt.Sprintf("%s?logout=1&client_id=%s", redirectURI, clientID)
			s.sendLogoutNotification(logoutURL)
		}
	}
	return nil
}

func (s *authServiceImpl) sendLogoutNotification(notificationURL string) {
	// SSRF 防护：拒绝指向内网/回环地址的通知目标
	if isPrivateURL(notificationURL) {
		facade.Warnf("拒绝发送登出通知：目标地址为内网/回环地址，URL: %s", notificationURL)
		return
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("POST", notificationURL, http.NoBody)
	if err != nil {
		facade.Errorf("创建登出通知请求失败: %v, URL: %s", err, notificationURL)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		facade.Errorf("发送登出通知失败: %v, URL: %s", err, notificationURL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		facade.Errorf("登出通知响应失败: %s, URL: %s", resp.Status, notificationURL)
		return
	}

	facade.Infof("登出通知发送成功: %s", notificationURL)
}

// isPrivateURL 判断 URL 是否指向内网、回环或链路本地地址（用于 SSRF 防护）
func isPrivateURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}

	// 主机名黑名单：localhost 及常见内网域名
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") ||
		strings.HasSuffix(lowerHost, ".internal") || strings.HasSuffix(lowerHost, ".local") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// 非 IP 形式的主机名（如公网域名），默认放行
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
}

func (s *authServiceImpl) GenerateAuthorizationCode(ctx context.Context, userID uint, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) (string, error) {
	code := GenerateRandomString(32)

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
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}

	_, err := dao.GetTokenDao().CreateAuthorizationCode(authCode)
	if err != nil {
		return "", errors.New("授权码生成失败")
	}

	return code, nil
}

func (s *authServiceImpl) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*model.AuthorizationCode, error) {
	authCode, err := dao.GetTokenDao().FindByCode(code)
	if err != nil {
		return nil, errors.New("授权码不存在")
	}

	if authCode.Used {
		return nil, errors.New("授权码已使用")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("授权码已过期")
	}

	if authCode.ClientID != clientID {
		return nil, errors.New("客户端ID不匹配")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("重定向URI不匹配")
	}

	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, errors.New("缺少code_verifier参数")
		}

		var expectedCodeChallenge string
		if authCode.CodeChallengeMethod == "S256" {
			hash := sha256.Sum256([]byte(codeVerifier))
			expectedCodeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
		} else {
			expectedCodeChallenge = codeVerifier
		}

		if authCode.CodeChallenge != expectedCodeChallenge {
			return nil, errors.New("code_verifier验证失败")
		}
	}

	err = dao.GetTokenDao().MarkAsUsed(authCode.ID)
	if err != nil {
		return nil, errors.New("授权码验证失败")
	}

	return authCode, nil
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func (s *authServiceImpl) GetJWKS(ctx context.Context) (*v1.JWKSResponse, error) {
	keyService := service.GetKeyService()
	if keyService == nil {
		return &v1.JWKSResponse{Keys: []v1.Key{}}, nil
	}

	currentKey, err := keyService.GetCurrentKey()
	if err != nil {
		return &v1.JWKSResponse{Keys: []v1.Key{}}, nil
	}

	publicKey, ok := currentKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("无效的公钥类型")
	}

	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	return &v1.JWKSResponse{
		Keys: []v1.Key{
			{
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				Kid: currentKey.ID,
				N:   n,
				E:   e,
			},
		},
	}, nil
}

func (s *authServiceImpl) Introspect(ctx context.Context, tokenString string, ip string, deviceFingerprint string) (*v1.IntrospectResponse, error) {
	claims, err := s.ValidateToken(ctx, tokenString, ip, deviceFingerprint)
	if err != nil {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	token, err := dao.GetTokenDao().FindByAccessToken(tokenString)
	if err != nil {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	if token.Revoked {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

	if time.Now().After(token.ExpiresAt) {
		return &v1.IntrospectResponse{
			Active: false,
		}, nil
	}

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
