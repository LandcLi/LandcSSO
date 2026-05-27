package auth

import (
	"context"
	"net/http"

	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/gin-gonic/gin"
)

var authControllerImpl authApi

// todo 针对第三方登录，还需要增加获取认证链接的接口，通过code获取access_token、refresh_token的接口
// 同时，需要增加一个接口，用于刷新access_token，并且SSO系统要维护refresh_token和access_token
type authApi interface {
	Login(ctx context.Context, req *v1.LoginRequest) (*v1.TokenResponse, error)
	ExchangeTempToken(ctx context.Context, req *v1.ExchangeTempTokenRequest) (*v1.TokenResponse, error)
	RefreshToken(ctx context.Context, req *v1.RefreshTokenRequest) (*v1.TokenResponse, error)
	RevokeToken(ctx context.Context, req *v1.RevokeTokenRequest) error
	Logout(ctx context.Context, req *v1.LogoutRequest) error
	GenerateAuthorizationCode(ctx context.Context, req *v1.AuthorizationCodeRequest) (string, error)
	ValidateAuthorizationCode(ctx context.Context, req *v1.ValidateAuthorizationCodeRequest) (*model.AuthorizationCode, error)
	GetThirdPartyAuthURL(ctx context.Context, req *v1.ThirdPartyAuthURLRequest) (*v1.ThirdPartyAuthURLResponse, error)
	Authorize(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.AuthorizationCodeResponse, error)
	Token(ctx context.Context, req *v1.TokenRequest) (*v1.TokenResponse, error)
	Introspect(ctx context.Context, req *v1.IntrospectRequest) (*v1.IntrospectResponse, error)
	GetJWKS(ctx context.Context) (*v1.JWKSResponse, error)
}

func RegisterAuthController(controller authApi) {
	authControllerImpl = controller
}

func GetAuthController() authApi {
	return authControllerImpl
}

func Login(c *gin.Context) {
	req := &v1.LoginRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.Login(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func ExchangeTempToken(c *gin.Context) {
	req := &v1.ExchangeTempTokenRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.ExchangeTempToken(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func RefreshToken(c *gin.Context) {
	req := &v1.RefreshTokenRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.RefreshToken(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func RevokeToken(c *gin.Context) {
	req := &v1.RevokeTokenRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	err := authControllerImpl.RevokeToken(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Token revoked successfully",
	})
}

func Logout(c *gin.Context) {
	req := &v1.LogoutRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	err := authControllerImpl.Logout(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

func GenerateAuthorizationCode(c *gin.Context) {
	req := &v1.AuthorizationCodeRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	code, err := authControllerImpl.GenerateAuthorizationCode(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": code,
	})
}

func ValidateAuthorizationCode(c *gin.Context) {
	req := &v1.ValidateAuthorizationCodeRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.ValidateAuthorizationCode(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func GetThirdPartyAuthURL(c *gin.Context) {
	req := &v1.ThirdPartyAuthURLRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.GetThirdPartyAuthURL(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func Authorize(c *gin.Context) {
	req := &v1.AuthorizationCodeRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	resp, err := authControllerImpl.Authorize(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func Token(c *gin.Context) {
	req := &v1.TokenRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	userAgent := c.GetHeader("User-Agent")
	ctx := context.WithValue(c.Request.Context(), "IP", ip)
	ctx = context.WithValue(ctx, "DeviceFingerprint", deviceFingerprint)
	ctx = context.WithValue(ctx, "UserAgent", userAgent)
	resp, err := authControllerImpl.Token(ctx, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func GetJWKS(c *gin.Context) {
	resp, err := authControllerImpl.GetJWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func Introspect(c *gin.Context) {
	req := &v1.IntrospectRequest{}
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}
	ip := c.ClientIP()
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	ctx := context.WithValue(c.Request.Context(), "IP", ip)
	ctx = context.WithValue(ctx, "DeviceFingerprint", deviceFingerprint)
	resp, err := authControllerImpl.Introspect(ctx, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, resp)
}
