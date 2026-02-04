package auth

import (
	"context"
	"errors"

	authApi "github.com/LandcLi/LandcSSO/api/auth"
	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	userapi "github.com/LandcLi/LandcUserManager/api/user"
	userv1api "github.com/LandcLi/LandcUserManager/api/user/v1"
)

func init() {
	if authApi.GetAuthController() == nil {
		authApi.RegisterAuthController(NewAuthController())
	}
}

type authController struct {
}

func NewAuthController() *authController {
	return &authController{}
}

func (c *authController) Login(ctx context.Context, req *v1.LoginRequest) (*v1.TokenResponse, error) {
	ip := ctx.Value("IP").(string)
	deviceFingerprint := ctx.Value("DeviceFingerprint").(string)
	userAgent := ctx.Value("UserAgent").(string)

	// 如果是第三方登录，需要根据verifyType获取对应的适配器，然后调用获取access_token、refresh_token的接口
	if req.AuthType == "THIRD_PARTY" {
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

	// 调用认证服务刷新令牌
	tokenResp, err := service.GetAuthService().RefreshToken(ctx, req.RefreshToken, ip, deviceFingerprint)
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

func (c *authController) GenerateAuthorizationCode(ctx context.Context, req *v1.AuthorizationCodeRequest) (string, error) {
	// 从上下文获取用户ID
	userID := ctx.Value("UserID").(uint)

	// 调用认证服务生成授权码
	return service.GetAuthService().GenerateAuthorizationCode(ctx, userID, req.ClientID, req.RedirectURI, req.Scope, req.State, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod)
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

	// 生成认证URL
	authURL, err := adapter.GenerateAuthURL(ctx, req.Params)
	if err != nil {
		return nil, err
	}

	return &v1.ThirdPartyAuthURLResponse{
		AuthURL: authURL,
	}, nil
}
