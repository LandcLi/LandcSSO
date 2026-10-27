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
	GenerateAuthorizationCode(ctx context.Context, req *v1.GenerateAuthorizationCodeRequest) (*v1.GenerateAuthCodeResponse, error)
	ValidateAuthorizationCode(ctx context.Context, req *v1.ValidateAuthorizationCodeRequest) (*model.AuthorizationCode, error)
	GetThirdPartyAuthURL(ctx context.Context, req *v1.ThirdPartyAuthURLRequest) (*v1.ThirdPartyAuthURLResponse, error)
	Authorize(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.AuthorizationCodeResponse, error)
	Token(ctx context.Context, req *v1.TokenRequest) (*v1.TokenResponse, error)
	Introspect(ctx context.Context, req *v1.IntrospectRequest) (*v1.IntrospectResponse, error)
	GetJWKS(ctx context.Context) (*v1.JWKSResponse, error)
}

// contextKey 请求元信息在 context 中的键类型。
//
// 用自定义类型而不是裸字符串（staticcheck SA1029）：字符串键跨包极易冲突，
// 任何引入了同名键的第三方包都可能静默覆盖。此前 LandcSSO 的 trace 就吃过
// 这个亏 —— 自定义类型写入、字符串读取，永远取不到值。
type contextKey string

const (
	ctxKeyIP        contextKey = "ip"
	ctxKeyDeviceFP  contextKey = "device_fingerprint"
	ctxKeyUserAgent contextKey = "user_agent"
	ctxKeyUserID    contextKey = "user_id"
)

// WithUserID 把已认证用户 ID 写入 context（由鉴权中间件调用）。
func WithUserID(ctx context.Context, userID uint) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// UserIDFromContext 取出已认证用户 ID，未认证时 ok 为 false。
func UserIDFromContext(ctx context.Context) (uint, bool) {
	id, ok := ctx.Value(ctxKeyUserID).(uint)
	return id, ok
}

// RequestInfoEnricher extracts IP, DeviceFingerprint, UserAgent from gin.Context into context.
func RequestInfoEnricher(ctx context.Context, c *gin.Context) context.Context {
	ctx = context.WithValue(ctx, ctxKeyIP, c.ClientIP())
	ctx = context.WithValue(ctx, ctxKeyDeviceFP, c.GetHeader("X-Device-Fingerprint"))
	ctx = context.WithValue(ctx, ctxKeyUserAgent, c.GetHeader("User-Agent"))
	return ctx
}

// RequestInfo 从 context 取出请求元信息。
//
// 用带 ok 的类型断言而不是裸断言：这些值只在经过 RequestInfoEnricher 的请求里
// 存在，裸断言（ctx.Value("IP").(string)）在 key 缺失时会直接 panic ——
// 而它恰好用于登出/撤销这类安全敏感路径。
func RequestInfo(ctx context.Context) (ip, deviceFingerprint, userAgent string) {
	ip, _ = ctx.Value(ctxKeyIP).(string)
	deviceFingerprint, _ = ctx.Value(ctxKeyDeviceFP).(string)
	userAgent, _ = ctx.Value(ctxKeyUserAgent).(string)
	return ip, deviceFingerprint, userAgent
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
