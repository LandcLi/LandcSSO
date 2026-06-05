package auth

import (
	"context"

	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/landc-go/frame/pkg/di"
	"github.com/gin-gonic/gin"
)

// AuthController defines the authentication controller interface.
type AuthController interface {
	Login(ctx context.Context, req *v1.LoginRequest) (*v1.TokenResponse, error)
	ExchangeTempToken(ctx context.Context, req *v1.ExchangeTempTokenRequest) (*v1.TokenResponse, error)
	RefreshToken(ctx context.Context, req *v1.RefreshTokenRequest) (*v1.TokenResponse, error)
	RevokeToken(ctx context.Context, req *v1.RevokeTokenRequest) error
	Logout(ctx context.Context, req *v1.LogoutRequest) error
	GenerateAuthorizationCode(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.GenerateAuthCodeResponse, error)
	ValidateAuthorizationCode(ctx context.Context, req *v1.ValidateAuthorizationCodeRequest) (*model.AuthorizationCode, error)
	GetThirdPartyAuthURL(ctx context.Context, req *v1.ThirdPartyAuthURLRequest) (*v1.ThirdPartyAuthURLResponse, error)
	Authorize(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.AuthorizationCodeResponse, error)
	Token(ctx context.Context, req *v1.TokenRequest) (*v1.TokenResponse, error)
	Introspect(ctx context.Context, req *v1.IntrospectRequest) (*v1.IntrospectResponse, error)
	GetJWKS(ctx context.Context) (*v1.JWKSResponse, error)
}

// RequestInfoEnricher extracts IP, DeviceFingerprint, UserAgent from gin.Context into context.
func RequestInfoEnricher(ctx context.Context, c *gin.Context) context.Context {
	ctx = context.WithValue(ctx, "IP", c.ClientIP())
	ctx = context.WithValue(ctx, "DeviceFingerprint", c.GetHeader("X-Device-Fingerprint"))
	ctx = context.WithValue(ctx, "UserAgent", c.GetHeader("User-Agent"))
	return ctx
}

// AuthGateway is the service gateway for authentication.
var AuthGateway = di.NewGateway[AuthController]("auth.controller")

// GetAuthController returns the registered AuthController implementation.
func GetAuthController() AuthController {
	return AuthGateway.Get()
}

// RegisterAuthController registers an AuthController implementation.
func RegisterAuthController(impl AuthController) {
	AuthGateway.Provide(impl)
}
