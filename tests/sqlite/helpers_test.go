package sqlite_test

import (
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/LandcLi/landc-go/frame/pkg/web"

	userapi "github.com/LandcLi/LandcUserManager/api/user"
	userv1 "github.com/LandcLi/LandcUserManager/api/user/v1"

	"github.com/LandcLi/LandcSSO/serverlib"
)

// buildRouter 用 serverlib 组装出完整的 SSO 路由，返回 gin 引擎。
func buildRouter(t *testing.T) *gin.Engine {
	t.Helper()
	server := web.New()
	if err := serverlib.RegisterToRouter(server); err != nil {
		t.Fatalf("register routes: %v", err)
	}
	return server.Engine()
}

// userService 取用户中心控制器（local 模式为进程内实现，remote 模式为 HTTP 代理）。
func userService() userapi.UserController {
	return userapi.UserGateway.Get()
}

// registerRequest 构造一个密码注册请求（authType=PASSWORD 时无需验证码）。
func registerRequest(username, password string) *userv1.RegisterRequest {
	return &userv1.RegisterRequest{
		Identifier:        username,
		Password:          password,
		AuthCode:          password,
		AuthType:          "PASSWORD",
		VerifyType:        "USERNAME",
		IP:                "127.0.0.1",
		DeviceFingerprint: "sso-sqlite-smoke",
		UserAgent:         "sso-sqlite-smoke-test",
	}
}
