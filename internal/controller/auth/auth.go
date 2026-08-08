package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	authApi "github.com/LandcLi/LandcSSO/api/auth"
	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	thirdparty "github.com/LandcLi/LandcSSO/internal/service_impl/third_party"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/security"
	userapi "github.com/LandcLi/LandcUserManager/api/user"
	userv1api "github.com/LandcLi/LandcUserManager/api/user/v1"
	"github.com/LandcLi/landc-go/frame/pkg/di"
)

func init() {
	di.Provide[authApi.AuthController]("auth.controller", NewAuthController())
}

type authController struct {
}

// Authorize implements [auth.authApi].
func (c *authController) Authorize(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.AuthorizationCodeResponse, error) {
	// 验证response_type
	if req.ResponseType != "code" {
		return nil, errors.New("response_type must be 'code'")
	}

	// state 参数必填，防止 CSRF（RFC 6749 §10.12）
	if req.State == "" {
		return nil, errors.New("state is required")
	}

	client, err := service.GetClientService().GetByClientID(req.ClientID)
	if err != nil {
		return nil, err
	}
	// 验证客户端状态
	if client.Status != 1 {
		return nil, errors.New("client is disabled")
	}
	// 严格校验 redirect_uri 必须在客户端注册列表内（RFC 6749 §3.1.2.3）
	if !isRedirectURIRegistered(client.RedirectURIs, req.RedirectURI) {
		return nil, errors.New("redirect_uri not registered for client")
	}
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// 生成授权码
	authorizationCode, err := service.GetAuthService().GenerateAuthorizationCode(ctx, userID, req.ClientID, req.RedirectURI, req.Scope, req.State, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod)
	if err != nil {
		return nil, err
	}
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", req.RedirectURI, authorizationCode, req.State)

	return &v1.AuthorizationCodeResponse{
		RedirectURI: redirectURL,
		Code:        authorizationCode,
		State:       req.State,
	}, nil
}

func NewAuthController() *authController {
	return &authController{}
}

// getUserIDFromContext 从 context 中提取已认证的用户ID，未认证时返回错误
func getUserIDFromContext(ctx context.Context) (uint, error) {
	ctxValue := ctx.Value("UserID")
	if ctxValue == nil {
		return 0, errors.New("未认证")
	}
	userID, ok := ctxValue.(uint)
	if !ok {
		return 0, errors.New("未认证")
	}
	return userID, nil
}

func (c *authController) Login(ctx context.Context, req *v1.LoginRequest) (*v1.TokenResponse, error) {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)
	userAgent := ctx.Value("UserAgent").(string)

	// 如果是第三方登录，需要根据verifyType获取对应的适配器，然后调用获取access_token、refresh_token的接口
	if req.AuthType == "THIRD_PARTY" {
		// 校验 CSRF 防伪 state（服务端生成，必须原样回传，一次性）
		if !thirdparty.ValidateAndConsumeState(req.State, req.VerifyType) {
			return nil, errors.New("state校验失败或已过期")
		}

		// 获取对应的适配器
		adapter, ok := service.GetThirdPartyAdapter(req.VerifyType)
		if !ok {
			return nil, errors.New("第三方登录适配器未找到")
		}

		// 通过code获取access_token、refresh_token和openId
		accessToken, refreshToken, openId, err := adapter.FetchAccessTokenAndRefreshToken(ctx, req.AuthCode, req.RedirectURI)
		if err != nil {
			return nil, err
		}

		// 调用用户服务登录，AuthCode需要替换为openId
		resp, err := userapi.GetUserController().Login(ctx, &userv1api.LoginRequest{
			Identifier:        openId,
			VerifyType:        req.VerifyType,
			AuthCode:          openId,
			AuthType:          req.AuthType,
			AccessToken:       accessToken,
			RefreshToken:      refreshToken,
			IP:                ip,
			DeviceFingerprint: deviceFingerprint,
			UserAgent:         userAgent,
		})
		if err != nil {
			return nil, err
		}

		// 调用认证服务登录
		tokenResp, err := service.GetAuthService().Login(ctx, resp.UserID, resp.DifferentLocation, resp.IsNewDevice, ip, deviceFingerprint, userAgent)
		if err != nil {
			return nil, err
		}

		return &v1.TokenResponse{
			AccessToken:  tokenResp.AccessToken,
			TokenType:    tokenResp.TokenType,
			ExpiresIn:    tokenResp.ExpiresIn,
			RefreshToken: tokenResp.RefreshToken,
			Scope:        tokenResp.Scope,
			IDToken:      tokenResp.IDToken,
			IsTmp:        tokenResp.IsTmp,
		}, nil
	}

	// 非第三方登录，调用用户服务登录
	resp, err := userapi.GetUserController().Login(ctx, &userv1api.LoginRequest{
		Identifier:        req.Identifier,
		VerifyType:        req.VerifyType,
		AuthCode:          req.AuthCode,
		AuthType:          req.AuthType,
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         userAgent,
	})
	if err != nil {
		return nil, err
	}

	// 调用认证服务登录
	tokenResp, err := service.GetAuthService().Login(ctx, resp.UserID, resp.DifferentLocation, resp.IsNewDevice, ip, deviceFingerprint, userAgent)
	if err != nil {
		return nil, err
	}

	return &v1.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
		IsTmp:        tokenResp.IsTmp,
	}, nil
}

func (c *authController) ExchangeTempToken(ctx context.Context, req *v1.ExchangeTempTokenRequest) (*v1.TokenResponse, error) {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)
	userAgent := ctx.Value("UserAgent").(string)

	// 调用认证服务兑换临时令牌
	tokenResp, err := service.GetAuthService().ExchangeTempToken(ctx, req.TempToken, ip, deviceFingerprint, userAgent)
	if err != nil {
		return nil, err
	}

	return &v1.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
		IsTmp:        tokenResp.IsTmp,
	}, nil
}

func (c *authController) RefreshToken(ctx context.Context, req *v1.RefreshTokenRequest) (*v1.TokenResponse, error) {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)

	// 调用认证服务刷新令牌（强制客户端认证）
	tokenResp, err := service.GetAuthService().RefreshToken(ctx, req.RefreshToken, req.ClientID, req.ClientSecret, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	return &v1.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
		IsTmp:        tokenResp.IsTmp,
	}, nil
}

func (c *authController) RevokeToken(ctx context.Context, req *v1.RevokeTokenRequest) error {
	// 调用认证服务撤销令牌
	return service.GetAuthService().RevokeToken(ctx, req.Token)
}

func (c *authController) Logout(ctx context.Context, req *v1.LogoutRequest) error {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)
	userAgent := ctx.Value("UserAgent").(string)

	// 从令牌中获取用户ID
	claims, err := service.GetAuthService().ValidateToken(ctx, req.Token, ip, deviceFingerprint)
	if err != nil {
		return err
	}

	// 调用认证服务登出
	return service.GetAuthService().Logout(ctx, claims.UserID, ip, deviceFingerprint, userAgent)
}

func (c *authController) GenerateAuthorizationCode(ctx context.Context, req *v1.GenerateAuthorizationCodeRequest) (*v1.GenerateAuthCodeResponse, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	code, err := service.GetAuthService().GenerateAuthorizationCode(ctx, userID, req.ClientID, req.RedirectURI, req.Scope, req.State, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod)
	if err != nil {
		return nil, err
	}
	return &v1.GenerateAuthCodeResponse{Code: code}, nil
}

func (c *authController) ValidateAuthorizationCode(ctx context.Context, req *v1.ValidateAuthorizationCodeRequest) (*model.AuthorizationCode, error) {
	// 调用认证服务验证授权码
	return service.GetAuthService().ValidateAuthorizationCode(ctx, req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
}

func (c *authController) GetThirdPartyAuthURL(ctx context.Context, req *v1.ThirdPartyAuthURLRequest) (*v1.ThirdPartyAuthURLResponse, error) {
	// 获取第三方适配器
	adapter, ok := service.GetThirdPartyAdapter(req.Provider)
	if !ok {
		return nil, errors.New("第三方登录适配器未找到")
	}

	// 服务端生成 CSRF 防伪 state 并保存（10 分钟有效，一次性）
	state := thirdparty.GenerateState(req.Provider)
	if req.Params == nil {
		req.Params = make(map[string]string)
	}
	req.Params["state"] = state

	// 生成认证URL
	authURL, err := adapter.GenerateAuthURL(ctx, req.Params)
	if err != nil {
		return nil, err
	}

	return &v1.ThirdPartyAuthURLResponse{
		AuthURL: authURL,
		State:   state,
	}, nil
}

func (c *authController) Token(ctx context.Context, req *v1.TokenRequest) (*v1.TokenResponse, error) {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)

	// 处理不同的授权类型
	switch req.GrantType {
	case "refresh_token":
		resp, err := service.GetAuthService().RefreshToken(ctx, req.RefreshToken, req.ClientID, req.ClientSecret, ip, deviceFingerprint)
		if err != nil {
			return nil, err
		}
		return &v1.TokenResponse{
			AccessToken:  resp.AccessToken,
			TokenType:    resp.TokenType,
			ExpiresIn:    resp.ExpiresIn,
			RefreshToken: resp.RefreshToken,
			Scope:        resp.Scope,
			IDToken:      resp.IDToken,
			IsTmp:        resp.IsTmp,
		}, nil
	case "password":
		// 处理密码授权
		loginReq := &v1.LoginRequest{
			Identifier: req.Username,
			AuthCode:   req.Password,
			AuthType:   "PASSWORD",
			VerifyType: "USERNAME",
		}

		resp, err := authApi.GetAuthController().Login(ctx, loginReq)
		if err != nil {
			return nil, err
		}
		return resp, nil
	case "authorization_code":
		// 处理授权码模式
		client, err := service.GetClientService().GetByClientID(req.ClientID)
		if err != nil {
			return nil, err
		}

		// 验证客户端密钥（恒定时间比较）
		if !security.VerifySecret(client.ClientSecret, req.ClientSecret) {
			return nil, errors.New("invalid_client")
		}

		// 验证授权码
		authCode, err := service.GetAuthService().ValidateAuthorizationCode(ctx, req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
		if err != nil {
			return nil, err
		}

		// 生成令牌
		resp, err := service.GetAuthService().GenerateTokens(ctx, authCode.UserID, req.ClientID, ip, deviceFingerprint)
		if err != nil {
			return nil, err
		}

		return &v1.TokenResponse{
			AccessToken:  resp.AccessToken,
			TokenType:    resp.TokenType,
			ExpiresIn:    resp.ExpiresIn,
			RefreshToken: resp.RefreshToken,
			Scope:        resp.Scope,
			IDToken:      resp.IDToken,
			IsTmp:        resp.IsTmp,
		}, nil
	case "client_credentials":
		// 处理客户端凭证模式

		client, err := service.GetClientService().GetByClientID(req.ClientID)
		if err != nil {
			return nil, err
		}

		// 验证客户端密钥（恒定时间比较）
		if !security.VerifySecret(client.ClientSecret, req.ClientSecret) {
			return nil, errors.New("invalid_client")
		}

		// 验证客户端状态
		if client.Status != 1 {
			return nil, errors.New("unauthorized_client")
		}
		// 生成令牌（客户端凭证模式下，userID为0表示无用户关联）
		resp, err := service.GetAuthService().GenerateTokens(ctx, 0, req.ClientID, ip, deviceFingerprint)
		if err != nil {
			return nil, err
		}

		return &v1.TokenResponse{
			AccessToken:  resp.AccessToken,
			TokenType:    resp.TokenType,
			ExpiresIn:    resp.ExpiresIn,
			RefreshToken: resp.RefreshToken,
			Scope:        resp.Scope,
			IDToken:      resp.IDToken,
			IsTmp:        resp.IsTmp,
		}, nil
	default:
		return nil, errors.New("unsupported_grant_type")
	}
}

func (c *authController) GetJWKS(ctx context.Context) (*v1.JWKSResponse, error) {
	// 调用认证服务获取JWKS
	return service.GetAuthService().GetJWKS(ctx)
}

// isRedirectURIRegistered 检查 redirectURI 是否在客户端注册的重定向 URI 列表中
func isRedirectURIRegistered(registeredURIsJSON, redirectURI string) bool {
	if registeredURIsJSON == "" || redirectURI == "" {
		return false
	}
	var registeredURIs []string
	if err := json.Unmarshal([]byte(registeredURIsJSON), &registeredURIs); err != nil {
		return false
	}
	for _, uri := range registeredURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

func (c *authController) Introspect(ctx context.Context, req *v1.IntrospectRequest) (*v1.IntrospectResponse, error) {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)

	// 验证客户端凭证（如果提供了）
	if req.ClientID != "" && req.ClientSecret != "" {
		client, err := service.GetClientService().GetByClientID(req.ClientID)
		if err != nil {
			return nil, errors.New("invalid_client")
		}

		if !security.VerifySecret(client.ClientSecret, req.ClientSecret) {
			return nil, errors.New("invalid_client")
		}
	}

	// 调用认证服务进行令牌验证
	resp, err := service.GetAuthService().Introspect(ctx, req.Token, ip, deviceFingerprint)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
