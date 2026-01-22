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
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/LandcLi/LandcSSO/pkg/logger"
	"github.com/google/uuid"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// AuthService 认证服务
type AuthService struct {
	userRepo           *repository.UserRepository
	tokenRepo          *repository.TokenRepository
	loginHistoryRepo   *repository.LoginHistoryRepository
	trustedDeviceRepo  *repository.TrustedDeviceRepository
	thirdPartyUserRepo *repository.ThirdPartyUserRepository
	clientService      *ClientService
	sessionService     *SessionService
	config             *config.Config
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
}

// NewAuthService 创建认证服务实例
func NewAuthService(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository, loginHistoryRepo *repository.LoginHistoryRepository, trustedDeviceRepo *repository.TrustedDeviceRepository, thirdPartyUserRepo *repository.ThirdPartyUserRepository, config *config.Config) *AuthService {
	// Go 1.20+ 不需要手动初始化随机数种子
	// 系统会自动初始化

	service := &AuthService{
		userRepo:           userRepo,
		tokenRepo:          tokenRepo,
		loginHistoryRepo:   loginHistoryRepo,
		trustedDeviceRepo:  trustedDeviceRepo,
		thirdPartyUserRepo: thirdPartyUserRepo,
		config:             config,
	}

	// 加载RSA密钥（如果配置了）
	if config.JWT.PrivateKeyPath != "" && config.JWT.PublicKeyPath != "" {
		privateKey, err := os.ReadFile(config.JWT.PrivateKeyPath)
		if err != nil {
			logger.Errorf(context.Background(), "读取私钥文件失败: %v", err)
		} else {
			privateKeyObj, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
			if err != nil {
				logger.Errorf(context.Background(), "解析私钥失败: %v", err)
			} else {
				service.privateKey = privateKeyObj
			}
		}

		publicKey, err := os.ReadFile(config.JWT.PublicKeyPath)
		if err != nil {
			logger.Errorf(context.Background(), "读取公钥文件失败: %v", err)
		} else {
			publicKeyObj, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
			if err != nil {
				logger.Errorf(context.Background(), "解析公钥失败: %v", err)
			} else {
				service.publicKey = publicKeyObj
			}
		}
	}

	return service
}

// SetClientService 设置客户端服务
func (s *AuthService) SetClientService(clientService *ClientService) {
	s.clientService = clientService
}

// SetSessionService 设置会话服务
func (s *AuthService) SetSessionService(sessionService *SessionService) {
	s.sessionService = sessionService
}

// Login 用户登录
func (s *AuthService) Login(req *model.UserLoginRequest, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 为了确保密码验证的准确性和安全性，每次登录都直接从数据库获取最新的密码哈希
	user, err := s.userRepo.FindByUsernameFromDB(req.Username)
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
	ctx := context.Background()

	// 生成6位数字验证码
	verifyCode := generateNumericCode(6)

	// 构建Redis键
	var key string

	if req.Email != "" {
		key = fmt.Sprintf("verify_code:email:%s:%s", req.Email, req.Action)
	} else if req.Phone != "" {
		key = fmt.Sprintf("verify_code:phone:%s:%s", req.Phone, req.Action)
	} else {
		return errors.New("邮箱或手机号不能为空")
	}

	// 存储验证码到Redis，设置5分钟过期
	redisClient := config.GetRedis()
	if redisClient == nil {
		logger.Errorf(ctx, "Redis客户端未初始化")
		return errors.New("验证码发送失败")
	}

	err := redisClient.Set(ctx, key, verifyCode, 5*time.Minute).Err()
	if err != nil {
		logger.Errorf(ctx, "存储验证码到Redis失败: %v", err)
		return errors.New("验证码发送失败")
	}

	// 发送验证码
	if req.Email != "" {
		// 发送邮件验证码
		err = s.sendMail(req.Email, "验证码", fmt.Sprintf("您的验证码是: %s，5分钟内有效", verifyCode))
	} else if req.Phone != "" {
		// 发送短信验证码
		err = s.sendSMS(req.Phone, verifyCode)
	}

	if err != nil {
		logger.Errorf(ctx, "发送验证码失败: %v", err)
		return errors.New("验证码发送失败")
	}

	return nil
}

// generateNumericCode 生成数字验证码
func generateNumericCode(length int) string {
	const charset = "0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// VerifyCodeLogin 验证码登录
func (s *AuthService) VerifyCodeLogin(req *model.VerifyCodeLoginRequest, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	ctx := context.Background()

	// 验证验证码
	var key string
	if req.Email != "" {
		key = fmt.Sprintf("verify_code:email:%s:login", req.Email)
	} else if req.Phone != "" {
		key = fmt.Sprintf("verify_code:phone:%s:login", req.Phone)
	} else {
		return nil, errors.New("邮箱或手机号不能为空")
	}

	// 从Redis获取验证码
	redisClient := config.GetRedis()
	if redisClient == nil {
		logger.Errorf(ctx, "Redis客户端未初始化")
		return nil, errors.New("验证码验证失败")
	}

	storedCode, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("验证码已过期或不存在")
		}
		logger.Errorf(ctx, "从Redis获取验证码失败: %v", err)
		return nil, errors.New("验证码验证失败")
	}

	// 验证验证码
	if storedCode != req.VerifyCode {
		return nil, errors.New("验证码错误")
	}

	// 验证码验证成功后删除
	_ = redisClient.Del(ctx, key).Err()

	// 查找用户
	var user *model.User

	if req.Email != "" {
		user, err = s.userRepo.FindByEmail(req.Email)
	} else if req.Phone != "" {
		user, err = s.userRepo.FindByPhone(req.Phone)
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
	thirdPartyUser, err := s.getThirdPartyUserInfo(req.Provider, req.Code)
	if err != nil {
		return nil, err
	}

	// 查找是否已存在第三方用户关联
	var user *model.User
	var link *model.ThirdPartyUserLink

	// 1. 首先根据OpenID和提供商查找关联
	if s.thirdPartyUserRepo != nil {
		link, err = s.thirdPartyUserRepo.FindByOpenIDAndProvider(thirdPartyUser.OpenID, req.Provider)
		if err == nil && link != nil {
			// 找到关联，获取用户信息
			user, err = s.userRepo.FindByID(link.UserID)
			if err == nil && user != nil {
				// 关联存在且用户有效
				return s.completeLogin(user, ip, deviceFingerprint, userAgent)
			}
		}

		// 2. 如果OpenID未找到，尝试通过UnionID查找
		if thirdPartyUser.UnionID != "" {
			link, err = s.thirdPartyUserRepo.FindByUnionID(thirdPartyUser.UnionID)
			if err == nil && link != nil {
				// 找到关联，获取用户信息
				user, err = s.userRepo.FindByID(link.UserID)
				if err == nil && user != nil {
					// 关联存在且用户有效
					return s.completeLogin(user, ip, deviceFingerprint, userAgent)
				}
			}
		}
	}

	// 3. 如果没有找到关联，尝试通过邮箱查找用户
	if thirdPartyUser.Email != "" {
		user, err = s.userRepo.FindByEmail(thirdPartyUser.Email)
		if err == nil && user != nil {
			// 找到邮箱匹配的用户，创建关联
			if s.thirdPartyUserRepo != nil {
				newLink := &model.ThirdPartyUserLink{
					UserID:   user.ID,
					Provider: req.Provider,
					OpenID:   thirdPartyUser.OpenID,
					UnionID:  thirdPartyUser.UnionID,
				}
				_, err = s.thirdPartyUserRepo.Create(newLink)
				if err != nil {
					// 创建关联失败不影响登录
				}
			}
			return s.completeLogin(user, ip, deviceFingerprint, userAgent)
		}
	}

	// 4. 如果没有找到任何关联，创建新用户
	// 创建新用户
	nickname := thirdPartyUser.Nickname
	if nickname == "" {
		nickname = "第三方用户"
	}

	user = &model.User{
		Username: "", // 第三方登录用户不需要用户名
		Email:    thirdPartyUser.Email,
		Password: "", // 第三方登录用户不需要密码
		Nickname: nickname,
		Phone:    thirdPartyUser.Phone,
		Status:   1,
	}
	user, err = s.userRepo.Create(user)
	if err != nil {
		return nil, errors.New("创建用户失败")
	}

	// 为新用户创建第三方关联
	if s.thirdPartyUserRepo != nil {
		newLink := &model.ThirdPartyUserLink{
			UserID:   user.ID,
			Provider: req.Provider,
			OpenID:   thirdPartyUser.OpenID,
			UnionID:  thirdPartyUser.UnionID,
		}
		_, err = s.thirdPartyUserRepo.Create(newLink)
		if err != nil {
			// 创建关联失败不影响登录
		}
	}

	// 完成登录
	return s.completeLogin(user, ip, deviceFingerprint, userAgent)
}

// completeLogin 完成登录流程
func (s *AuthService) completeLogin(user *model.User, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
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
	case "alipay":
		return s.getAlipayUserInfo(code)
	default:
		return nil, errors.New("不支持的第三方登录提供商")
	}
}

// ValidateWechatRedirectURI 验证微信重定向URI
func (s *AuthService) ValidateWechatRedirectURI(redirectURI string) error {
	// 检查配置
	if s.config == nil || s.config.ThirdParty.Wechat.AppId == "" {
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
	if s.config.ThirdParty.Wechat.RedirectUri != "" {
		// 解析配置中的redirect_uri
		configURI, err := url.Parse(s.config.ThirdParty.Wechat.RedirectUri)
		if err == nil && configURI.Host != "" {
			if parsedURI.Host != configURI.Host {
				return errors.New("redirect_uri的域名与配置不一致")
			}
		}
	}

	return nil
}

// GenerateWechatAuthURL 生成微信授权链接
func (s *AuthService) GenerateWechatAuthURL(redirectURI string, state string) (string, error) {
	// 检查配置
	if s.config == nil || s.config.ThirdParty.Wechat.AppId == "" {
		return "", errors.New("微信登录配置未设置")
	}

	// 验证redirect_uri
	if err := s.ValidateWechatRedirectURI(redirectURI); err != nil {
		return "", err
	}

	// 构建授权链接
	authURL := "https://open.weixin.qq.com/connect/qrconnect"

	// 对redirect_uri进行URL编码
	encodedRedirectURI := url.QueryEscape(redirectURI)

	// 构建参数
	params := fmt.Sprintf("appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_login&state=%s#wechat_redirect",
		s.config.ThirdParty.Wechat.AppId, encodedRedirectURI, state)

	// 返回完整的授权链接
	return authURL + "?" + params, nil
}

// RefreshWechatToken 刷新微信access_token
func (s *AuthService) RefreshWechatToken(refreshToken string) (string, error) {
	ctx := context.Background()

	// 检查配置
	if s.config == nil || s.config.ThirdParty.Wechat.AppId == "" || s.config.ThirdParty.Wechat.AppSecret == "" {
		return "", errors.New("微信登录配置未设置")
	}

	// 构建刷新token的URL
	refreshURL := "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	refreshParams := fmt.Sprintf("appid=%s&grant_type=refresh_token&refresh_token=%s",
		s.config.ThirdParty.Wechat.AppId, refreshToken)

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

// getWechatUserInfo 获取微信用户信息
func (s *AuthService) getWechatUserInfo(code string) (*model.ThirdPartyUser, error) {
	ctx := context.Background()

	// 检查配置
	if s.config == nil || s.config.ThirdParty.Wechat.AppId == "" || s.config.ThirdParty.Wechat.AppSecret == "" {
		return nil, errors.New("微信登录配置未设置")
	}

	// 1. 通过code获取access_token
	tokenURL := "https://api.weixin.qq.com/sns/oauth2/access_token"
	tokenParams := fmt.Sprintf("appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		s.config.ThirdParty.Wechat.AppId, s.config.ThirdParty.Wechat.AppSecret, code)

	tokenResp, err := http.Get(tokenURL + "?" + tokenParams)
	if err != nil {
		logger.Errorf(ctx, "获取微信access_token失败: %v", err)
		return nil, errors.New("获取微信令牌失败")
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		OpenID       string `json:"openid"`
		Scope        string `json:"scope"`
		UnionID      string `json:"unionid"`
		Errcode      int    `json:"errcode"`
		Errmsg       string `json:"errmsg"`
	}

	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		logger.Errorf(ctx, "解析微信access_token响应失败: %v", err)
		return nil, errors.New("解析微信令牌响应失败")
	}

	if tokenData.Errcode != 0 {
		logger.Errorf(ctx, "微信API错误: %d, %s", tokenData.Errcode, tokenData.Errmsg)
		return nil, errors.New("微信API错误: " + tokenData.Errmsg)
	}

	// 2. 使用access_token获取用户信息
	userInfoURL := "https://api.weixin.qq.com/sns/userinfo"
	userInfoParams := fmt.Sprintf("access_token=%s&openid=%s", tokenData.AccessToken, tokenData.OpenID)

	userInfoResp, err := http.Get(userInfoURL + "?" + userInfoParams)
	if err != nil {
		logger.Errorf(ctx, "获取微信用户信息失败: %v", err)
		return nil, errors.New("获取微信用户信息失败")
	}
	defer userInfoResp.Body.Close()

	var userInfoData struct {
		OpenID     string `json:"openid"`
		Nickname   string `json:"nickname"`
		Sex        int    `json:"sex"`
		Province   string `json:"province"`
		City       string `json:"city"`
		Country    string `json:"country"`
		HeadImgURL string `json:"headimgurl"`
		UnionID    string `json:"unionid"`
		Errcode    int    `json:"errcode"`
		Errmsg     string `json:"errmsg"`
	}

	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfoData); err != nil {
		logger.Errorf(ctx, "解析微信用户信息响应失败: %v", err)
		return nil, errors.New("解析微信用户信息响应失败")
	}

	// 处理access_token过期的情况
	if userInfoData.Errcode == 40001 {
		// access_token过期，尝试使用refresh_token刷新
		newAccessToken, err := s.RefreshWechatToken(tokenData.RefreshToken)
		if err != nil {
			logger.Errorf(ctx, "刷新微信access_token失败: %v", err)
			return nil, errors.New("微信令牌已过期且刷新失败")
		}

		// 使用新的access_token重新获取用户信息
		userInfoParams = fmt.Sprintf("access_token=%s&openid=%s", newAccessToken, tokenData.OpenID)
		userInfoResp, err = http.Get(userInfoURL + "?" + userInfoParams)
		if err != nil {
			logger.Errorf(ctx, "重新获取微信用户信息失败: %v", err)
			return nil, errors.New("获取微信用户信息失败")
		}
		defer userInfoResp.Body.Close()

		// 重新解析响应
		if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfoData); err != nil {
			logger.Errorf(ctx, "重新解析微信用户信息响应失败: %v", err)
			return nil, errors.New("解析微信用户信息响应失败")
		}

		if userInfoData.Errcode != 0 {
			logger.Errorf(ctx, "微信API错误: %d, %s", userInfoData.Errcode, userInfoData.Errmsg)
			return nil, errors.New("微信API错误: " + userInfoData.Errmsg)
		}
	} else if userInfoData.Errcode != 0 {
		logger.Errorf(ctx, "微信API错误: %d, %s", userInfoData.Errcode, userInfoData.Errmsg)
		return nil, errors.New("微信API错误: " + userInfoData.Errmsg)
	}

	// 转换性别
	gender := ""
	switch userInfoData.Sex {
	case 1:
		gender = "男"
	case 2:
		gender = "女"
	default:
		gender = "未知"
	}

	return &model.ThirdPartyUser{
		Provider: "wechat",
		OpenID:   userInfoData.OpenID,
		UnionID:  userInfoData.UnionID,
		Nickname: userInfoData.Nickname,
		Avatar:   userInfoData.HeadImgURL,
		Email:    "",
		Phone:    "",
		Gender:   gender,
		Country:  userInfoData.Country,
		Province: userInfoData.Province,
		City:     userInfoData.City,
	}, nil
}

// getDingTalkUserInfo 获取钉钉用户信息
func (s *AuthService) getDingTalkUserInfo(code string) (*model.ThirdPartyUser, error) {
	ctx := context.Background()

	// 检查配置
	if s.config == nil || s.config.ThirdParty.Dingtalk.AppId == "" || s.config.ThirdParty.Dingtalk.AppSecret == "" {
		return nil, errors.New("钉钉登录配置未设置")
	}

	// 1. 通过code获取access_token
	tokenURL := "https://oapi.dingtalk.com/sns/gettoken"
	tokenParams := fmt.Sprintf("appid=%s&appsecret=%s",
		s.config.ThirdParty.Dingtalk.AppId, s.config.ThirdParty.Dingtalk.AppSecret)

	tokenResp, err := http.Get(tokenURL + "?" + tokenParams)
	if err != nil {
		logger.Errorf(ctx, "获取钉钉access_token失败: %v", err)
		return nil, errors.New("获取钉钉令牌失败")
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		Errcode     int    `json:"errcode"`
		Errmsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		logger.Errorf(ctx, "解析钉钉access_token响应失败: %v", err)
		return nil, errors.New("解析钉钉令牌响应失败")
	}

	if tokenData.Errcode != 0 {
		logger.Errorf(ctx, "钉钉API错误: %d, %s", tokenData.Errcode, tokenData.Errmsg)
		return nil, errors.New("钉钉API错误: " + tokenData.Errmsg)
	}

	// 2. 使用access_token和code获取用户信息
	userInfoURL := "https://oapi.dingtalk.com/sns/getuserinfo_bycode"

	// 构建请求体
	reqBody := map[string]string{
		"tmp_auth_code": code,
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		logger.Errorf(ctx, "构建钉钉用户信息请求失败: %v", err)
		return nil, errors.New("构建请求失败")
	}

	// 创建请求
	req, err := http.NewRequest("POST", userInfoURL, strings.NewReader(string(reqJSON)))
	if err != nil {
		logger.Errorf(ctx, "创建钉钉用户信息请求失败: %v", err)
		return nil, errors.New("创建请求失败")
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-acs-dingtalk-access-token", tokenData.AccessToken)

	// 发送请求
	client := &http.Client{Timeout: 10 * time.Second}
	userInfoResp, err := client.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取钉钉用户信息失败: %v", err)
		return nil, errors.New("获取钉钉用户信息失败")
	}
	defer userInfoResp.Body.Close()

	var userInfoData struct {
		Errcode  int    `json:"errcode"`
		Errmsg   string `json:"errmsg"`
		UserInfo struct {
			OpenID  string `json:"openid"`
			UnionID string `json:"unionid"`
			Nick    string `json:"nick"`
			Avatar  string `json:"avatar"`
		} `json:"user_info"`
	}

	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfoData); err != nil {
		logger.Errorf(ctx, "解析钉钉用户信息响应失败: %v", err)
		return nil, errors.New("解析钉钉用户信息响应失败")
	}

	if userInfoData.Errcode != 0 {
		logger.Errorf(ctx, "钉钉API错误: %d, %s", userInfoData.Errcode, userInfoData.Errmsg)
		return nil, errors.New("钉钉API错误: " + userInfoData.Errmsg)
	}

	return &model.ThirdPartyUser{
		Provider: "dingtalk",
		OpenID:   userInfoData.UserInfo.OpenID,
		UnionID:  userInfoData.UserInfo.UnionID,
		Nickname: userInfoData.UserInfo.Nick,
		Avatar:   userInfoData.UserInfo.Avatar,
		Email:    "",
		Phone:    "",
		Gender:   "",
		Country:  "",
		Province: "",
		City:     "",
	}, nil
}

// ValidateGitHubRedirectURI 验证GitHub重定向URI
func (s *AuthService) ValidateGitHubRedirectURI(redirectURI string) error {
	// 检查配置
	if s.config == nil || s.config.ThirdParty.Github.ClientId == "" {
		return errors.New("GitHub登录配置未设置")
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
	// 注意：这里应该与GitHub OAuth应用注册的域名进行比较
	// 实际项目中，应该从配置中读取允许的域名列表进行验证
	if s.config.ThirdParty.Github.RedirectUri != "" {
		// 解析配置中的redirect_uri
		configURI, err := url.Parse(s.config.ThirdParty.Github.RedirectUri)
		if err == nil && configURI.Host != "" {
			if parsedURI.Host != configURI.Host {
				return errors.New("redirect_uri的域名与配置不一致")
			}
		}
	}

	return nil
}

// GenerateGitHubAuthURL 生成GitHub授权链接
func (s *AuthService) GenerateGitHubAuthURL(redirectURI string, state string, scope string, codeChallenge string, codeChallengeMethod string) (string, error) {
	// 检查配置
	if s.config == nil || s.config.ThirdParty.Github.ClientId == "" {
		return "", errors.New("GitHub登录配置未设置")
	}

	// 验证redirect_uri
	if err := s.ValidateGitHubRedirectURI(redirectURI); err != nil {
		return "", err
	}

	// 构建授权链接
	authURL := "https://github.com/login/oauth/authorize"

	// 对redirect_uri进行URL编码
	encodedRedirectURI := url.QueryEscape(redirectURI)

	// 设置默认scope
	if scope == "" {
		scope = "user:email"
	}

	// 构建参数
	params := fmt.Sprintf("client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		s.config.ThirdParty.Github.ClientId, encodedRedirectURI, scope, state)

	// 添加PKCE参数
	if codeChallenge != "" {
		params += "&code_challenge=" + url.QueryEscape(codeChallenge)
		if codeChallengeMethod != "" {
			params += "&code_challenge_method=" + codeChallengeMethod
		} else {
			params += "&code_challenge_method=S256"
		}
	}

	// 返回完整的授权链接
	return authURL + "?" + params, nil
}

// getGitHubUserInfo 获取GitHub用户信息
func (s *AuthService) getGitHubUserInfo(code string) (*model.ThirdPartyUser, error) {
	ctx := context.Background()

	// 检查配置
	if s.config == nil || s.config.ThirdParty.Github.ClientId == "" || s.config.ThirdParty.Github.ClientSecret == "" {
		return nil, errors.New("GitHub登录配置未设置")
	}

	// 1. 通过code获取access_token
	tokenURL := "https://github.com/login/oauth/access_token"

	// 构建请求体
	reqBody := strings.NewReader(fmt.Sprintf("client_id=%s&client_secret=%s&code=%s",
		s.config.ThirdParty.Github.ClientId, s.config.ThirdParty.Github.ClientSecret, code))

	// 创建请求
	req, err := http.NewRequest("POST", tokenURL, reqBody)
	if err != nil {
		logger.Errorf(ctx, "创建GitHub令牌请求失败: %v", err)
		return nil, errors.New("创建GitHub令牌请求失败")
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// 发送请求
	client := &http.Client{Timeout: 10 * time.Second}
	tokenResp, err := client.Do(req)
	if err != nil {
		logger.Errorf(ctx, "获取GitHub access_token失败: %v", err)
		return nil, errors.New("获取GitHub令牌失败")
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}

	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		logger.Errorf(ctx, "解析GitHub access_token响应失败: %v", err)
		return nil, errors.New("解析GitHub令牌响应失败")
	}

	if tokenData.Error != "" {
		logger.Errorf(ctx, "GitHub API错误: %s", tokenData.Error)
		return nil, errors.New("GitHub API错误: " + tokenData.Error)
	}

	if tokenData.AccessToken == "" {
		return nil, errors.New("未获取到GitHub访问令牌")
	}

	// 2. 使用access_token获取用户信息
	userInfoURL := "https://api.github.com/user"

	// 创建请求
	userInfoReq, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		logger.Errorf(ctx, "创建GitHub用户信息请求失败: %v", err)
		return nil, errors.New("创建GitHub用户信息请求失败")
	}

	// 设置请求头
	userInfoReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userInfoReq.Header.Set("Accept", "application/vnd.github.v3+json")

	// 发送请求
	userInfoResp, err := client.Do(userInfoReq)
	if err != nil {
		logger.Errorf(ctx, "获取GitHub用户信息失败: %v", err)
		return nil, errors.New("获取GitHub用户信息失败")
	}
	defer userInfoResp.Body.Close()

	var userInfoData struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		Bio       string `json:"bio"`
		Location  string `json:"location"`
		Error     string `json:"error"`
	}

	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfoData); err != nil {
		logger.Errorf(ctx, "解析GitHub用户信息响应失败: %v", err)
		return nil, errors.New("解析GitHub用户信息响应失败")
	}

	if userInfoData.Error != "" {
		logger.Errorf(ctx, "GitHub API错误: %s", userInfoData.Error)
		return nil, errors.New("GitHub API错误: " + userInfoData.Error)
	}

	// 3. 如果email为空，尝试获取用户的公开邮箱
	if userInfoData.Email == "" {
		emailsURL := "https://api.github.com/user/emails"
		emailsReq, err := http.NewRequest("GET", emailsURL, nil)
		if err == nil {
			emailsReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
			emailsReq.Header.Set("Accept", "application/vnd.github.v3+json")

			emailsResp, err := client.Do(emailsReq)
			if err == nil {
				defer emailsResp.Body.Close()

				var emailsData []struct {
					Email    string `json:"email"`
					Primary  bool   `json:"primary"`
					Verified bool   `json:"verified"`
				}

				if json.NewDecoder(emailsResp.Body).Decode(&emailsData) == nil {
					for _, email := range emailsData {
						if email.Primary && email.Verified {
							userInfoData.Email = email.Email
							break
						}
					}
				}
			}
		}
	}

	nickname := userInfoData.Name
	if nickname == "" {
		nickname = userInfoData.Login
	}

	return &model.ThirdPartyUser{
		Provider: "github",
		OpenID:   fmt.Sprintf("%d", userInfoData.ID),
		UnionID:  fmt.Sprintf("%d", userInfoData.ID),
		Nickname: nickname,
		Avatar:   userInfoData.AvatarURL,
		Email:    userInfoData.Email,
		Phone:    "",
		Gender:   "",
		Country:  "",
		Province: "",
		City:     userInfoData.Location,
	}, nil
}

// ValidateAlipayRedirectURI 验证支付宝重定向URI
func (s *AuthService) ValidateAlipayRedirectURI(redirectURI string) error {
	// 检查配置
	if s.config == nil || s.config.ThirdParty.Alipay.AppId == "" {
		return errors.New("支付宝登录配置未设置")
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
	// 注意：这里应该与支付宝开放平台审核通过的域名进行比较
	// 实际项目中，应该从配置中读取允许的域名列表进行验证
	if s.config.ThirdParty.Alipay.RedirectUri != "" {
		// 解析配置中的redirect_uri
		configURI, err := url.Parse(s.config.ThirdParty.Alipay.RedirectUri)
		if err == nil && configURI.Host != "" {
			if parsedURI.Host != configURI.Host {
				return errors.New("redirect_uri的域名与配置不一致")
			}
		}
	}

	return nil
}

// GenerateAlipayAuthURL 生成支付宝授权链接
func (s *AuthService) GenerateAlipayAuthURL(redirectURI string, state string) (string, error) {
	// 检查配置
	if s.config == nil || s.config.ThirdParty.Alipay.AppId == "" {
		return "", errors.New("支付宝登录配置未设置")
	}

	// 验证redirect_uri
	if err := s.ValidateAlipayRedirectURI(redirectURI); err != nil {
		return "", err
	}

	// 构建授权链接
	authURL := "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"

	// 对redirect_uri进行URL编码
	encodedRedirectURI := url.QueryEscape(redirectURI)

	// 构建参数
	params := fmt.Sprintf("app_id=%s&redirect_uri=%s&scope=auth_user&state=%s",
		s.config.ThirdParty.Alipay.AppId, encodedRedirectURI, state)

	// 返回完整的授权链接
	return authURL + "?" + params, nil
}

// getAlipayUserInfo 获取支付宝用户信息
func (s *AuthService) getAlipayUserInfo(code string) (*model.ThirdPartyUser, error) {
	ctx := context.Background()

	// 检查配置
	if s.config == nil || s.config.ThirdParty.Alipay.AppId == "" || s.config.ThirdParty.Alipay.AppSecret == "" {
		return nil, errors.New("支付宝登录配置未设置")
	}

	// 1. 通过auth_code换取access_token及userId
	tokenURL := "https://openapi.alipay.com/gateway.do"

	// 构建请求参数
	reqParams := map[string]string{
		"app_id":     s.config.ThirdParty.Alipay.AppId,
		"method":     "alipay.system.oauth.token",
		"format":     "JSON",
		"charset":    "UTF-8",
		"sign_type":  "RSA2",
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
		"version":    "1.0",
		"grant_type": "authorization_code",
		"code":       code,
	}

	// TODO: 这里需要添加签名逻辑
	// 实际项目中，需要根据支付宝文档生成签名

	// 构建请求URL
	paramsStr := ""
	for k, v := range reqParams {
		paramsStr += k + "=" + url.QueryEscape(v) + "&"
	}
	paramsStr = paramsStr[:len(paramsStr)-1]

	tokenResp, err := http.Get(tokenURL + "?" + paramsStr)
	if err != nil {
		logger.Errorf(ctx, "获取支付宝access_token失败: %v", err)
		return nil, errors.New("获取支付宝令牌失败")
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AlipaySystemOauthTokenResponse struct {
			AccessToken  string `json:"access_token"`
			ExpiresIn    int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
			UserId       string `json:"user_id"`
			ReExpiresIn  int    `json:"re_expires_in"`
			AuthStart    string `json:"auth_start"`
		} `json:"alipay_system_oauth_token_response"`
		ErrorResponse struct {
			Code    string `json:"code"`
			Msg     string `json:"msg"`
			SubCode string `json:"sub_code"`
			SubMsg  string `json:"sub_msg"`
		} `json:"error_response"`
	}

	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		logger.Errorf(ctx, "解析支付宝access_token响应失败: %v", err)
		return nil, errors.New("解析支付宝令牌响应失败")
	}

	// 检查是否有错误
	if tokenData.ErrorResponse.Code != "" {
		logger.Errorf(ctx, "支付宝API错误: %s, %s", tokenData.ErrorResponse.SubCode, tokenData.ErrorResponse.SubMsg)
		return nil, errors.New("支付宝API错误: " + tokenData.ErrorResponse.SubMsg)
	}

	if tokenData.AlipaySystemOauthTokenResponse.AccessToken == "" {
		return nil, errors.New("未获取到支付宝访问令牌")
	}

	// 2. 使用access_token获取用户信息
	userInfoURL := "https://openapi.alipay.com/gateway.do"

	// 构建请求参数
	userInfoParams := map[string]string{
		"app_id":     s.config.ThirdParty.Alipay.AppId,
		"method":     "alipay.user.info.share",
		"format":     "JSON",
		"charset":    "UTF-8",
		"sign_type":  "RSA2",
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
		"version":    "1.0",
		"auth_token": tokenData.AlipaySystemOauthTokenResponse.AccessToken,
	}

	// TODO: 这里需要添加签名逻辑
	// 实际项目中，需要根据支付宝文档生成签名

	// 构建请求URL
	userInfoParamsStr := ""
	for k, v := range userInfoParams {
		userInfoParamsStr += k + "=" + url.QueryEscape(v) + "&"
	}
	userInfoParamsStr = userInfoParamsStr[:len(userInfoParamsStr)-1]

	userInfoResp, err := http.Get(userInfoURL + "?" + userInfoParamsStr)
	if err != nil {
		logger.Errorf(ctx, "获取支付宝用户信息失败: %v", err)
		return nil, errors.New("获取支付宝用户信息失败")
	}
	defer userInfoResp.Body.Close()

	var userInfoData struct {
		AlipayUserInfoShareResponse struct {
			UserId   string `json:"user_id"`
			Avatar   string `json:"avatar"`
			City     string `json:"city"`
			Province string `json:"province"`
			NickName string `json:"nick_name"`
			Gender   string `json:"gender"`
			Email    string `json:"email"`
		} `json:"alipay_user_info_share_response"`
		ErrorResponse struct {
			Code    string `json:"code"`
			Msg     string `json:"msg"`
			SubCode string `json:"sub_code"`
			SubMsg  string `json:"sub_msg"`
		} `json:"error_response"`
	}

	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfoData); err != nil {
		logger.Errorf(ctx, "解析支付宝用户信息响应失败: %v", err)
		return nil, errors.New("解析支付宝用户信息响应失败")
	}

	// 检查是否有错误
	if userInfoData.ErrorResponse.Code != "" {
		logger.Errorf(ctx, "支付宝API错误: %s, %s", userInfoData.ErrorResponse.SubCode, userInfoData.ErrorResponse.SubMsg)
		return nil, errors.New("支付宝API错误: " + userInfoData.ErrorResponse.SubMsg)
	}

	return &model.ThirdPartyUser{
		Provider: "alipay",
		OpenID:   userInfoData.AlipayUserInfoShareResponse.UserId,
		UnionID:  userInfoData.AlipayUserInfoShareResponse.UserId,
		Nickname: userInfoData.AlipayUserInfoShareResponse.NickName,
		Avatar:   userInfoData.AlipayUserInfoShareResponse.Avatar,
		Email:    userInfoData.AlipayUserInfoShareResponse.Email,
		Phone:    "",
		Gender:   userInfoData.AlipayUserInfoShareResponse.Gender,
		Country:  "",
		Province: userInfoData.AlipayUserInfoShareResponse.Province,
		City:     userInfoData.AlipayUserInfoShareResponse.City,
	}, nil
}

// BiometricLogin 生物识别登录
func (s *AuthService) BiometricLogin(req *model.BiometricLoginRequest, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 验证生物识别信息
	// TODO: 实现生物识别验证
	// 暂时简单验证设备指纹和用户ID
	if req.UserID == 0 || req.DeviceFingerprint == "" {
		return nil, errors.New("无效的生物识别信息")
	}

	// 查找用户
	user, err := s.userRepo.FindByID(req.UserID)
	if err != nil || user == nil {
		return nil, errors.New("用户不存在")
	}

	// 检测异地登录
	isAbnormal := s.detectAbnormalLogin(user.ID, ip, deviceFingerprint)

	// 记录登录历史
	var remark string
	if isAbnormal {
		remark = "异地登录检测"
	} else {
		remark = "生物识别登录"
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

// StartScanCodeLogin 开始扫码登录
func (s *AuthService) StartScanCodeLogin() (string, error) {
	// 生成二维码ID
	qrcodeID := uuid.New().String()

	// 存储二维码状态到Redis
	ctx := context.Background()
	key := fmt.Sprintf("scan_code_login:%s", qrcodeID)
	// 设置二维码状态为待扫描，有效期5分钟
	err := s.tokenRepo.GetRedisClient().Set(ctx, key, "pending", 5*time.Minute).Err()
	if err != nil {
		return "", err
	}

	return qrcodeID, nil
}

// VerifyScanCodeLogin 验证扫码登录
func (s *AuthService) VerifyScanCodeLogin(qrcodeID string, userID uint) error {
	// 验证二维码是否存在
	ctx := context.Background()
	key := fmt.Sprintf("scan_code_login:%s", qrcodeID)

	// 检查二维码状态
	_, err := s.tokenRepo.GetRedisClient().Get(ctx, key).Result()
	if err != nil {
		return errors.New("二维码不存在或已过期")
	}

	// 更新二维码状态为已确认
	err = s.tokenRepo.GetRedisClient().Set(ctx, key, fmt.Sprintf("confirmed:%d", userID), 5*time.Minute).Err()
	if err != nil {
		return err
	}

	return nil
}

// CheckScanCodeLoginStatus 检查扫码登录状态
func (s *AuthService) CheckScanCodeLoginStatus(qrcodeID string) (uint, error) {
	// 检查二维码状态
	ctx := context.Background()
	key := fmt.Sprintf("scan_code_login:%s", qrcodeID)

	status, err := s.tokenRepo.GetRedisClient().Get(ctx, key).Result()
	if err != nil {
		return 0, errors.New("二维码不存在或已过期")
	}

	// 解析状态
	if strings.HasPrefix(status, "confirmed:") {
		// 提取用户ID
		userIDStr := strings.TrimPrefix(status, "confirmed:")
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			return 0, errors.New("无效的用户ID")
		}
		return uint(userID), nil
	}

	return 0, errors.New("二维码尚未确认")
}

// CompleteScanCodeLogin 完成扫码登录
func (s *AuthService) CompleteScanCodeLogin(qrcodeID string, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error) {
	// 检查扫码登录状态
	userID, err := s.CheckScanCodeLoginStatus(qrcodeID)
	if err != nil {
		return nil, err
	}

	// 查找用户
	user, err := s.userRepo.FindByID(userID)
	if err != nil || user == nil {
		return nil, errors.New("用户不存在")
	}

	// 检测异地登录
	isAbnormal := s.detectAbnormalLogin(user.ID, ip, deviceFingerprint)

	// 记录登录历史
	var remark string
	if isAbnormal {
		remark = "异地登录检测"
	} else {
		remark = "扫码登录"
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
			_, err := s.tokenRepo.Update(oldestToken)
			if err != nil {
				logger.Errorf(context.Background(), "撤销旧令牌失败: %v", err)
			}
		}
	}

	return nil
}

// generateAccessToken 生成访问令牌
func (s *AuthService) generateAccessToken(userID uint, clientID string, ip string, deviceFingerprint string) (string, int, error) {
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
func (s *AuthService) ValidateToken(tokenString string, ip string, deviceFingerprint string) (*model.Claims, error) {
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
	// 1. 撤销用户的所有令牌
	err := s.revokeUserTokens(userID)
	if err != nil {
		// 令牌撤销失败不影响登出流程
	}

	// 2. 清理用户的所有会话
	if s.sessionService != nil {
		err = s.sessionService.DeleteUserSessions(userID)
		if err != nil {
			// 会话清理失败不影响登出流程
		}
	}

	// 3. 通知所有已登录的应用
	err = s.notifyClients(userID)
	if err != nil {
		// 通知失败不影响登出流程
	}

	// 4. 记录登出审计日志
	if s.loginHistoryRepo != nil {
		_, err := s.userRepo.FindByID(userID)
		if err == nil {
			// 记录登出历史
			loginHistory := &model.LoginHistory{
				UserID:            userID,
				IP:                ip,
				DeviceFingerprint: deviceFingerprint,
				UserAgent:         userAgent,
				LoginTime:         time.Now(), // 使用LoginTime字段记录时间，保持与登录记录一致
				Status:            0,          // 0表示登出
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
	ctx := context.Background()

	// 1. 查询用户的所有活跃令牌
	tokens, err := s.tokenRepo.FindByUserID(userID)
	if err != nil {
		logger.Errorf(ctx, "查询用户活跃令牌失败: %v", err)
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
		client, err := s.clientService.GetByClientID(clientID)
		if err != nil {
			logger.Errorf(ctx, "获取客户端信息失败: %v", err)
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
func (s *AuthService) sendLogoutNotification(url string) {
	ctx := context.Background()

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 发送GET请求
	resp, err := client.Get(url)
	if err != nil {
		logger.Errorf(ctx, "发送登出通知失败: %v, URL: %s", err, url)
		return
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logger.Errorf(ctx, "登出通知响应失败: %s, URL: %s", resp.Status, url)
		return
	}

	logger.Infof(ctx, "登出通知发送成功: %s", url)
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

	// 清除用户缓存，确保下次登录时使用最新的密码哈希
	if s.userRepo != nil {
		_ = s.userRepo.ClearUserCache(user)
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

// sendMail 发送邮件验证码
func (s *AuthService) sendMail(to string, subject string, body string) error {
	if s.config.Mail.Host == "" {
		logger.Warnf(context.Background(), "邮件服务未配置，跳过发送")
		return nil // 开发环境下可以跳过实际发送
	}

	// 构建邮件内容
	mailContent := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		s.config.Mail.From, to, subject, body)

	// 发送邮件
	addr := fmt.Sprintf("%s:%d", s.config.Mail.Host, s.config.Mail.Port)
	auth := smtp.PlainAuth("", s.config.Mail.Username, s.config.Mail.Password, s.config.Mail.Host)

	if s.config.Mail.UseSSL {
		return smtp.SendMail(addr, auth, s.config.Mail.From, []string{to}, []byte(mailContent))
	} else {
		// 非SSL连接
		c, dialErr := smtp.Dial(addr)
		if dialErr != nil {
			return dialErr
		}
		defer c.Close()

		if helloErr := c.Hello("localhost"); helloErr != nil {
			return helloErr
		}

		if authErr := c.Auth(auth); authErr != nil {
			return authErr
		}

		if mailErr := c.Mail(s.config.Mail.From); mailErr != nil {
			return mailErr
		}

		if rcptErr := c.Rcpt(to); rcptErr != nil {
			return rcptErr
		}

		w, dataErr := c.Data()
		if dataErr != nil {
			return dataErr
		}
		defer w.Close()

		_, writeErr := w.Write([]byte(mailContent))
		return writeErr
	}
}

// sendSMS 发送短信验证码
func (s *AuthService) sendSMS(phone string, code string) error {
	if s.config.SMS.Provider == "" {
		logger.Warnf(context.Background(), "短信服务未配置，跳过发送")
		return nil // 开发环境下可以跳过实际发送
	}

	// 根据不同的短信提供商实现不同的发送逻辑
	switch s.config.SMS.Provider {
	case "aliyun":
		// 阿里云短信发送实现（示例）
		return s.sendAliyunSMS(phone, code)
	case "tencent":
		// 腾讯云短信发送实现（示例）
		return s.sendTencentSMS(phone, code)
	default:
		logger.Errorf(context.Background(), "不支持的短信提供商: %s", s.config.SMS.Provider)
		return errors.New("不支持的短信提供商")
	}
}

// sendAliyunSMS 发送阿里云短信
func (s *AuthService) sendAliyunSMS(phone string, code string) error {
	// 这里实现阿里云短信发送的实际代码
	// 示例代码，实际需要引入阿里云SDK
	logger.Infof(context.Background(), "发送阿里云短信到 %s: 验证码 %s", phone, code)
	// TODO: 实现阿里云短信发送SDK调用
	return nil
}

// sendTencentSMS 发送腾讯云短信
func (s *AuthService) sendTencentSMS(phone string, code string) error {
	// 这里实现腾讯云短信发送的实际代码
	// 示例代码，实际需要引入腾讯云SDK
	logger.Infof(context.Background(), "发送腾讯云短信到 %s: 验证码 %s", phone, code)
	// TODO: 实现腾讯云短信发送SDK调用
	return nil
}
