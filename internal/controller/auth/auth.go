package auth

import (
	"context"

	authApi "github.com/LandcLi/LandcSSO/api/auth"
	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
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

	// 调用用户服务登录
	resp, err := userapi.GetUserController().Login(ctx, &userv1api.LoginRequest{
		Identifier:        req.Identifier,
		VerifyType:        req.VerifyType,
		AuthCode:          req.AuthCode,
		AuthType:          req.AuthType,
		AccessToken:       req.AccessToken,
		RefreshToken:      req.RefreshToken,
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
	}, nil
}
