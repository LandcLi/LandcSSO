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
	"gorm.io/gorm"
)

func init() {
	if service.GetAuthService() == nil {
		service.RegisterAuthService(NewAuthServiceImpl())
	}
}

type authServiceImpl struct{}

// NewAuthServiceImpl 构造认证服务。
// 不在构造期读取配置：本类型的实例在包 init() 中创建，
// 此时配置/DB 尚未就绪，提前读取会 panic（且任何 import 本包的宿主都会连带崩溃）。
// 所有依赖改为在调用期惰性获取。
func NewAuthServiceImpl() *authServiceImpl {
	return &authServiceImpl{}
}

// cfg 惰性获取配置，始终返回非 nil（缺失时返回空配置以免调用点 nil panic）。
func (s *authServiceImpl) cfg() *config.Config {
	if cfg := config.GetConfig(); cfg != nil {
		return cfg
	}
	return &config.Config{}
}

// generateAccessToken 生成访问令牌（expiresIn 秒）
func (s *authServiceImpl) generateAccessToken(userID uint, username string, clientID string, ip string, deviceFingerprint string) (string, int, error) {
	expiresIn := s.cfg().JWT.AccessTokenExpiry
	token, err := frameauth.GenerateTokenWithOpts(userID, username, frameauth.GenerateTokenOption{
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
func (s *authServiceImpl) generateRefreshToken(userID uint, username string, clientID string) (string, int, error) {
	expiresIn := s.cfg().JWT.RefreshTokenExpiry
	token, err := frameauth.GenerateTokenWithOpts(userID, username, frameauth.GenerateTokenOption{
		ClientID:   clientID,
		TokenType:  "refresh",
		ExpireTime: time.Duration(expiresIn) * time.Second,
	})
	if err != nil {
		return "", 0, errors.New("刷新令牌生成失败")
	}
	return token, expiresIn, nil
}

// generateTempToken 生成临时token
func (s *authServiceImpl) generateTempToken(ctx context.Context, userID uint, username string, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	tokenString, err := frameauth.GenerateTokenWithOpts(userID, username, frameauth.GenerateTokenOption{
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
			"username":           username,
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

func (s *authServiceImpl) Login(ctx context.Context, userID uint, username string, differentLocation bool, isNewDevice bool, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	if differentLocation || isNewDevice {
		return s.generateTempToken(ctx, userID, username, ip, deviceFingerprint, userAgent)
	}
	return s.generateTokens(ctx, userID, username, "", ip, deviceFingerprint)
}

// generateTokens 生成令牌
func (s *authServiceImpl) generateTokens(ctx context.Context, userID uint, username string, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	if s.cfg().JWT.MaxConcurrentSessions > 0 {
		if err := s.checkConcurrentSessions(ctx, userID); err != nil {
			return nil, err
		}
	}

	// 生成访问令牌
	accessToken, expiresIn, err := s.generateAccessToken(userID, username, clientID, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	// 生成刷新令牌
	refreshToken, refreshExpiresIn, err := s.generateRefreshToken(userID, username, clientID)
	if err != nil {
		return nil, err
	}

	// 保存令牌
	token := &model.Token{
		UserID:            userID,
		Username:          username,
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

func (s *authServiceImpl) checkConcurrentSessions(ctx context.Context, userID uint) error {
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

	if len(validTokens) >= s.cfg().JWT.MaxConcurrentSessions {
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
			} else {
				// 同步写撤销缓存，让被踢下线的令牌尽快被拒绝
				s.markRevokedInCache(ctx, oldestToken.AccessToken, revokeCacheTTL(oldestToken.ExpiresAt))
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

	// 撤销检查：JWT 是无状态的，签名有效不代表仍然可用。
	//
	// 此前这里漏了这一步，导致 revoke-token / logout / 并发会话踢下线全部
	// 「假失效」——数据库里 marked revoked，令牌却照常通行到过期。
	//
	// 临时令牌（temp）不写入 tokens 表（只存 Redis 或在 claims 里），
	// 因此不参与数据库校验。
	if claims.TokenType == "access" || claims.TokenType == "" {
		revoked, err := s.isAccessTokenRevoked(ctx, tokenString)
		if err != nil {
			// 数据库不可用时按失败关闭处理：鉴权是安全边界，
			// 宁可拒绝也不要放行一个可能已撤销的令牌。
			facade.Errorf("校验令牌撤销状态失败，按拒绝处理: %v", err)
			return nil, errors.New("令牌状态校验失败")
		}
		if revoked {
			return nil, errors.New("令牌已失效")
		}
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
					username, _ := tempTokenData["username"].(string)
					rc.Del(ctx, tempTokenKey)
					return s.generateTokens(ctx, uint(userID), username, "", ip, deviceFingerprint)
				}
			}
		}
	}

	// Redis不可用或验证失败时，直接验证JWT获取用户ID
	claims, err := frameauth.ParseToken(tempToken)
	if err != nil {
		return nil, errors.New("临时令牌不存在或已过期")
	}

	return s.generateTokens(ctx, claims.UserID, claims.Username, "", ip, deviceFingerprint)
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

	newTokens, err := s.generateTokens(ctx, token.UserID, token.Username, token.ClientID, ip, deviceFingerprint)
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

// GenerateTokens 为服务端流程签发令牌（如 client_credentials）。
// 这类调用没有登录用户，username 留空。
func (s *authServiceImpl) GenerateTokens(ctx context.Context, userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	return s.generateTokens(ctx, userID, "", clientID, ip, deviceFingerprint)
}

func (s *authServiceImpl) RevokeToken(ctx context.Context, tokenString string) error {
	if err := s.revokeByTokenString(ctx, tokenString); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// RFC 7009 §2.2：撤销一个不存在或已失效的令牌应视为成功。
			// 若按「令牌不存在」报错，调用方就能借响应差异探测某个令牌是否有效，
			// 等于给攻击者提供了一个令牌有效性探针。
			//
			// 常见触发场景：客户端拿着新设备登录下发的临时令牌来撤销 ——
			// 临时令牌本就不落 tokens 表，无需撤销。
			return nil
		}
		return errors.New("令牌撤销失败")
	}
	return nil
}

func (s *authServiceImpl) Logout(ctx context.Context, userID uint, ip string, deviceFingerprint string, userAgent string) error {
	_ = s.revokeUserTokens(ctx, userID)

	_ = service.GetSessionService().DeleteUserSessions(userID)

	_ = s.notifyClients(userID)

	return nil
}

// revokeUserTokens 撤销某用户的全部令牌（登出、强制下线）。
//
// 先取出令牌原文写撤销缓存，再批量置 revoked。缓存只是加速后续的拒绝路径，
// 写失败不影响正确性 —— ValidateToken 最终以数据库为准。
func (s *authServiceImpl) revokeUserTokens(ctx context.Context, userID uint) error {
	if tokens, err := dao.GetTokenDao().FindByUserID(userID); err == nil {
		for _, t := range tokens {
			if !t.Revoked {
				s.markRevokedInCache(ctx, t.AccessToken, revokeCacheTTL(t.ExpiresAt))
			}
		}
	}
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
		Iss:       s.cfg().JWT.Issuer,
		Sub:       claims.UserID,
		Aud:       claims.ClientID,
	}, nil
}
