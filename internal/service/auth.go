package service

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"math/rand"
	"time"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/LandcLi/LandcSSO/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthService 认证服务
type AuthService struct {
	userRepo          *repository.UserRepository
	tokenRepo         *repository.TokenRepository
	loginHistoryRepo  *repository.LoginHistoryRepository
	trustedDeviceRepo *repository.TrustedDeviceRepository
	config            *config.Config
	privateKey        *rsa.PrivateKey
	publicKey         *rsa.PublicKey
}

// NewAuthService 创建认证服务实例
func NewAuthService(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository, loginHistoryRepo *repository.LoginHistoryRepository, trustedDeviceRepo *repository.TrustedDeviceRepository, config *config.Config) *AuthService {
	service := &AuthService{
		userRepo:          userRepo,
		tokenRepo:         tokenRepo,
		loginHistoryRepo:  loginHistoryRepo,
		trustedDeviceRepo: trustedDeviceRepo,
		config:            config,
	}

	// 加载RSA密钥（如果配置了）
	if config.JWT.PrivateKeyPath != "" && config.JWT.PublicKeyPath != "" {
		privateKey, err := ioutil.ReadFile(config.JWT.PrivateKeyPath)
		if err == nil {
			service.privateKey, _ = jwt.ParseRSAPrivateKeyFromPEM(privateKey)
		}

		publicKey, err := ioutil.ReadFile(config.JWT.PublicKeyPath)
		if err == nil {
			service.publicKey, _ = jwt.ParseRSAPublicKeyFromPEM(publicKey)
		}
	}

	return service
}

// Login 用户登录
func (s *AuthService) Login(req *model.UserLoginRequest, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 查找用户
	user, err := s.userRepo.FindByUsername(req.Username)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	// 验证密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, errors.New("密码错误")
	}

	// 检查用户状态
	if user.Status != 1 {
		return nil, errors.New("用户已禁用")
	}

	// 处理设备信任机制
	s.handleTrustedDevice(user.ID, deviceFingerprint, ip, userAgent)

	// 检测异地登录
	isAbnormal := s.detectAbnormalLogin(user.ID, ip, deviceFingerprint)

	// 记录登录历史
	var remark string
	if isAbnormal {
		remark = "异地登录检测"
	} else {
		remark = "正常登录"
	}
	loginHistory := &model.LoginHistory{
		UserID:            user.ID,
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		LoginTime:         time.Now(),
		Status:            1,
		IsAbnormal:        isAbnormal,
		Remark:            remark,
	}
	if s.loginHistoryRepo != nil {
		s.loginHistoryRepo.Create(loginHistory)
	}

	// 生成令牌
	return s.generateTokens(user.ID, "", ip, deviceFingerprint)
}

// handleTrustedDevice 处理设备信任机制
func (s *AuthService) handleTrustedDevice(userID uint, deviceFingerprint string, ip string, userAgent string) {
	if s.trustedDeviceRepo == nil || deviceFingerprint == "" {
		return
	}

	// 查找是否已存在信任设备
	device, err := s.trustedDeviceRepo.FindByUserIDAndFingerprint(userID, deviceFingerprint)
	if err != nil {
		// 设备不存在，创建新的信任设备
		newDevice := &model.TrustedDevice{
			UserID:            userID,
			DeviceFingerprint: deviceFingerprint,
			DeviceName:        userAgent, // 暂时使用用户代理作为设备名称
			LastLoginIP:       ip,
			FirstLoginTime:    time.Now(),
			LastLoginTime:     time.Now(),
		}
		s.trustedDeviceRepo.Create(newDevice)
	} else {
		// 设备已存在，更新最后登录时间和IP
		device.LastLoginTime = time.Now()
		device.LastLoginIP = ip
		s.trustedDeviceRepo.Update(device)
	}
}

// SendVerifyCode 发送验证码
func (s *AuthService) SendVerifyCode(req *model.VerifyCodeRequest) error {
	// 生成6位验证码
	_ = generateRandomString(6)

	// 存储验证码到Redis，设置5分钟过期
	_ = "verify_code:" + req.Email + ":" + req.Phone + ":" + req.Action
	// 这里应该使用Redis存储验证码，暂时使用内存存储
	// TODO: 实现Redis存储验证码

	// 模拟发送验证码
	if req.Email != "" {
		// 发送邮件验证码
		// TODO: 实现邮件发送
	} else if req.Phone != "" {
		// 发送短信验证码
		// TODO: 实现短信发送
	} else {
		return errors.New("邮箱或手机号不能为空")
	}

	return nil
}

// VerifyCodeLogin 验证码登录
func (s *AuthService) VerifyCodeLogin(req *model.VerifyCodeLoginRequest, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 验证验证码
	// TODO: 实现验证码验证逻辑

	// 查找用户
	var user *model.User
	var err error

	if req.Email != "" {
		user, err = s.userRepo.FindByEmail(req.Email)
	} else if req.Phone != "" {
		user, err = s.userRepo.FindByPhone(req.Phone)
	} else {
		return nil, errors.New("邮箱或手机号不能为空")
	}

	if err != nil {
		return nil, errors.New("用户不存在")
	}

	// 检查用户状态
	if user.Status != 1 {
		return nil, errors.New("用户已禁用")
	}

	// 检测异地登录
	isAbnormal := s.detectAbnormalLogin(user.ID, ip, deviceFingerprint)

	// 记录登录历史
	var remark string
	if isAbnormal {
		remark = "异地登录检测"
	} else {
		remark = "正常登录"
	}
	loginHistory := &model.LoginHistory{
		UserID:            user.ID,
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		LoginTime:         time.Now(),
		Status:            1,
		IsAbnormal:        isAbnormal,
		Remark:            remark,
	}
	if s.loginHistoryRepo != nil {
		s.loginHistoryRepo.Create(loginHistory)
	}

	// 生成令牌
	return s.generateTokens(user.ID, "", ip, deviceFingerprint)
}

// ThirdPartyLogin 第三方登录
func (s *AuthService) ThirdPartyLogin(req *model.ThirdPartyLoginRequest, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 获取第三方用户信息
	_, err := s.getThirdPartyUserInfo(req.Provider, req.Code)
	if err != nil {
		return nil, err
	}

	// 查找是否已存在关联
	// TODO: 实现第三方用户关联查找

	// 如果不存在关联，创建新用户
	// TODO: 实现新用户创建逻辑

	// 检测异地登录
	isAbnormal := s.detectAbnormalLogin(1, ip, deviceFingerprint) // 暂时使用用户ID 1

	// 记录登录历史
	var remark string
	if isAbnormal {
		remark = "异地登录检测"
	} else {
		remark = "正常登录"
	}
	loginHistory := &model.LoginHistory{
		UserID:            1, // 暂时使用用户ID 1
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
		LoginTime:         time.Now(),
		Status:            1,
		IsAbnormal:        isAbnormal,
		Remark:            remark,
	}
	if s.loginHistoryRepo != nil {
		s.loginHistoryRepo.Create(loginHistory)
	}

	// 生成令牌
	return s.generateTokens(1, "", ip, deviceFingerprint) // 暂时使用用户ID 1
}

// getThirdPartyUserInfo 获取第三方用户信息
func (s *AuthService) getThirdPartyUserInfo(provider string, code string) (*model.ThirdPartyUser, error) {
	// 根据提供商获取用户信息
	switch provider {
	case "wechat":
		return s.getWechatUserInfo(code)
	case "dingtalk":
		return s.getDingTalkUserInfo(code)
	case "github":
		return s.getGitHubUserInfo(code)
	default:
		return nil, errors.New("不支持的第三方登录提供商")
	}
}

// getWechatUserInfo 获取微信用户信息
func (s *AuthService) getWechatUserInfo(code string) (*model.ThirdPartyUser, error) {
	// TODO: 实现微信用户信息获取
	return &model.ThirdPartyUser{
		Provider: "wechat",
		OpenID:   "test_openid",
		UnionID:  "test_unionid",
		Nickname: "微信用户",
		Avatar:   "https://example.com/avatar.jpg",
		Email:    "",
		Phone:    "",
		Gender:   "",
		Country:  "",
		Province: "",
		City:     "",
	}, nil
}

// getDingTalkUserInfo 获取钉钉用户信息
func (s *AuthService) getDingTalkUserInfo(code string) (*model.ThirdPartyUser, error) {
	// TODO: 实现钉钉用户信息获取
	return &model.ThirdPartyUser{
		Provider: "dingtalk",
		OpenID:   "test_openid",
		UnionID:  "test_unionid",
		Nickname: "钉钉用户",
		Avatar:   "https://example.com/avatar.jpg",
		Email:    "",
		Phone:    "",
		Gender:   "",
		Country:  "",
		Province: "",
		City:     "",
	}, nil
}

// getGitHubUserInfo 获取GitHub用户信息
func (s *AuthService) getGitHubUserInfo(code string) (*model.ThirdPartyUser, error) {
	// TODO: 实现GitHub用户信息获取
	return &model.ThirdPartyUser{
		Provider: "github",
		OpenID:   "test_openid",
		UnionID:  "test_unionid",
		Nickname: "GitHub用户",
		Avatar:   "https://example.com/avatar.jpg",
		Email:    "github@example.com",
		Phone:    "",
		Gender:   "",
		Country:  "",
		Province: "",
		City:     "",
	}, nil
}

// Register 用户注册
func (s *AuthService) Register(req *model.UserRegisterRequest) (*model.UserResponse, error) {
	// 检查用户名是否已存在
	existingUser, err := s.userRepo.FindByUsername(req.Username)
	if err == nil && existingUser != nil {
		return nil, errors.New("用户名已存在")
	}

	// 检查邮箱是否已存在
	existingEmail, err := s.userRepo.FindByEmail(req.Email)
	if err == nil && existingEmail != nil {
		return nil, errors.New("邮箱已存在")
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}

	// 创建用户
	user := &model.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
		Nickname: req.Nickname,
		Phone:    req.Phone,
		Status:   1,
	}

	// 保存用户
	user, err = s.userRepo.Create(user)
	if err != nil {
		return nil, errors.New("用户创建失败")
	}

	return user.ToResponse(), nil
}

// generateTokens 生成令牌
func (s *AuthService) generateTokens(userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	// 检查并发会话数限制
	if s.config != nil && s.config.JWT.MaxConcurrentSessions > 0 {
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

	_, err = s.tokenRepo.Create(token)
	if err != nil {
		return nil, errors.New("令牌保存失败")
	}

	return &model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Scope:        "openid profile email",
	}, nil
}

// checkConcurrentSessions 检查并发会话数限制
func (s *AuthService) checkConcurrentSessions(userID uint) error {
	if s.tokenRepo == nil {
		return nil
	}

	// 获取用户的所有有效令牌
	tokens, err := s.tokenRepo.FindByUserID(userID)
	if err != nil {
		return nil
	}

	// 检查会话数是否超过限制
	if len(tokens) >= s.config.JWT.MaxConcurrentSessions {
		// 超过限制，踢掉最旧的会话
		// 按创建时间排序，找到最旧的令牌
		var oldestToken *model.Token
		for _, token := range tokens {
			if oldestToken == nil || token.CreatedAt.Before(oldestToken.CreatedAt) {
				oldestToken = token
			}
		}

		// 撤销最旧的令牌
		if oldestToken != nil {
			// 这里应该调用撤销令牌的方法
			// TODO: 实现令牌撤销逻辑
		}
	}

	return nil
}

// generateAccessToken 生成访问令牌
func (s *AuthService) generateAccessToken(userID uint, clientID string, ip string, deviceFingerprint string) (string, int, error) {
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

	// 如果userID不为0，获取用户信息
	if userID != 0 {
		// 使用缓存减少数据库访问
		user, err := s.userRepo.FindByID(userID)
		if err != nil {
			return "", 0, errors.New("用户不存在")
		}
		claims["username"] = user.Username
		claims["email"] = user.Email
	} else {
		// client_credentials模式下，使用客户端信息
		claims["username"] = "client"
		claims["email"] = "client@example.com"
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
func (s *AuthService) generateRefreshToken(userID uint, clientID string) (string, int, error) {
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
func (s *AuthService) ValidateToken(tokenString string, ip string, deviceFingerprint string) (*model.Claims, error) {
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
	userID := uint(claims["user_id"].(float64))
	username := claims["username"].(string)
	email := claims["email"].(string)
	scope := claims["scope"].(string)
	clientID := claims["client_id"].(string)

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
func (s *AuthService) RefreshToken(refreshToken string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	// 查找刷新令牌
	token, err := s.tokenRepo.FindByRefreshToken(refreshToken)
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
	newTokens, err := s.generateTokens(token.UserID, token.ClientID, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	// 撤销旧令牌
	token.Revoked = true
	_, err = s.tokenRepo.Update(token)
	if err != nil {
		ctx := context.Background()
		logger.Errorf(ctx, "撤销旧令牌失败: %v", err)
	}

	return newTokens, nil
}

// GenerateTokens 生成令牌（公开方法）
func (s *AuthService) GenerateTokens(userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error) {
	return s.generateTokens(userID, clientID, ip, deviceFingerprint)
}

// RevokeToken 撤销令牌
func (s *AuthService) RevokeToken(tokenString string) error {
	// 查找令牌
	token, err := s.tokenRepo.FindByAccessToken(tokenString)
	if err != nil {
		return errors.New("令牌不存在")
	}

	// 撤销令牌
	token.Revoked = true
	_, err = s.tokenRepo.Update(token)
	if err != nil {
		return errors.New("令牌撤销失败")
	}

	return nil
}

// Logout 用户登出
func (s *AuthService) Logout(userID uint, ip string, deviceFingerprint string, userAgent string) error {
	// 撤销用户的所有令牌
	err := s.revokeUserTokens(userID)
	if err != nil {
		// 令牌撤销失败不影响登出流程
	}

	// 通知所有已登录的应用
	err = s.notifyClients(userID)
	if err != nil {
		// 通知失败不影响登出流程
	}

	// 记录登出审计日志
	if s.loginHistoryRepo != nil {
		_, err := s.userRepo.FindByID(userID)
		if err == nil {
			// 记录登出历史
			loginHistory := &model.LoginHistory{
				UserID:            userID,
				IP:                ip,
				DeviceFingerprint: deviceFingerprint,
				UserAgent:         userAgent,
				LoginTime:         time.Now(),
				Status:            0, // 0表示登出
				IsAbnormal:        false,
				Remark:            "用户主动登出",
			}
			s.loginHistoryRepo.Create(loginHistory)
		}
	}

	return nil
}

// revokeUserTokens 撤销用户的所有令牌
func (s *AuthService) revokeUserTokens(userID uint) error {
	if s.tokenRepo == nil {
		return nil
	}

	// 撤销用户的所有令牌
	return s.tokenRepo.RevokeByUserID(userID)
}

// notifyClients 通知所有已登录的应用
func (s *AuthService) notifyClients(userID uint) error {
	// TODO: 实现通知客户端的逻辑
	// 1. 查询用户的所有活跃会话，获取关联的客户端应用
	// 2. 向每个客户端应用发送登出通知（通过回调URL）

	return nil
}

// GenerateAuthorizationCode 生成授权码
func (s *AuthService) GenerateAuthorizationCode(userID uint, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) (string, error) {
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
	_, err := s.tokenRepo.CreateAuthorizationCode(authCode)
	if err != nil {
		return "", errors.New("授权码生成失败")
	}

	return code, nil
}

// ValidateAuthorizationCode 验证授权码
func (s *AuthService) ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*model.AuthorizationCode, error) {
	// 查找授权码
	authCode, err := s.tokenRepo.FindByCode(code)
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
	err = s.tokenRepo.MarkAsUsed(authCode.ID)
	if err != nil {
		return nil, errors.New("授权码验证失败")
	}

	return authCode, nil
}

// GetUserProfile 获取用户资料
func (s *AuthService) GetUserProfile(userID uint) (*model.UserResponse, error) {
	// 查找用户
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	// 转换为响应对象
	return user.ToResponse(), nil
}

// UpdateUserProfile 更新用户资料
func (s *AuthService) UpdateUserProfile(userID uint, nickname, avatar, phone string) (*model.UserResponse, error) {
	// 查找用户
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	// 更新用户资料
	if nickname != "" {
		user.Nickname = nickname
	}
	if avatar != "" {
		user.Avatar = avatar
	}
	if phone != "" {
		user.Phone = phone
	}

	// 保存更新
	user, err = s.userRepo.Update(user)
	if err != nil {
		return nil, errors.New("更新用户资料失败")
	}

	// 转换为响应对象
	return user.ToResponse(), nil
}

// ChangePassword 修改用户密码
func (s *AuthService) ChangePassword(userID uint, oldPassword, newPassword string) error {
	// 查找用户
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// 验证旧密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword))
	if err != nil {
		return errors.New("旧密码错误")
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("密码加密失败")
	}

	// 更新密码
	user.Password = string(hashedPassword)
	_, err = s.userRepo.Update(user)
	if err != nil {
		return errors.New("修改密码失败")
	}

	return nil
}

// detectAbnormalLogin 检测异地登录
func (s *AuthService) detectAbnormalLogin(userID uint, ip string, deviceFingerprint string) bool {
	if s.loginHistoryRepo == nil {
		return false
	}

	// 查找用户最近的登录记录
	latestLogin, err := s.loginHistoryRepo.FindLatestByUserID(userID)
	if err != nil {
		// 没有历史登录记录，认为是第一次登录，不标记为异常
		return false
	}

	// 检查IP地址是否相同
	if latestLogin.IP != ip {
		// IP地址不同，检查设备指纹是否相同
		if latestLogin.DeviceFingerprint != "" && latestLogin.DeviceFingerprint != deviceFingerprint {
			// IP和设备指纹都不同，标记为异地登录
			return true
		}
	}

	return false
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
