package service

import (
	"context"

	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/LandcLi/LandcSSO/model"
)

var authServiceImpl authService

func RegisterAuthService(authService authService) {
	authServiceImpl = authService
}
func GetAuthService() authService {
	return authServiceImpl
}

type authService interface {
	// Login 签发用户令牌。username 来自 LandcUserManager 的登录响应（用户档案在 LUM），
	// 写进令牌 claims 供下游按用户名判断。
	Login(ctx context.Context, userID uint, username string, differentLocation bool, isNewDevice bool, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error)
	ExchangeTempToken(ctx context.Context, tempToken string, ip string, deviceFingerprint string, userAgent string) (*model.TokenResponse, error)
	ValidateToken(ctx context.Context, tokenString string, ip string, deviceFingerprint string) (*model.Claims, error)
	RefreshToken(ctx context.Context, refreshToken string, clientID string, clientSecret string, ip string, deviceFingerprint string) (*model.TokenResponse, error)
	GenerateTokens(ctx context.Context, userID uint, clientID string, ip string, deviceFingerprint string) (*model.TokenResponse, error)
	RevokeToken(ctx context.Context, tokenString string) error
	Logout(ctx context.Context, userID uint, ip string, deviceFingerprint string, userAgent string) error
	GenerateAuthorizationCode(ctx context.Context, userID uint, clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) (string, error)
	ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*model.AuthorizationCode, error)
	Introspect(ctx context.Context, tokenString string, ip string, deviceFingerprint string) (*v1.IntrospectResponse, error)
	GetJWKS(ctx context.Context) (*v1.JWKSResponse, error)
}
