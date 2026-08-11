package api

import (
	"github.com/LandcLi/LandcSSO/api/auth"
	"github.com/LandcLi/LandcSSO/api/client"
	authcontroller "github.com/LandcLi/LandcSSO/internal/controller/auth"
	"github.com/LandcLi/landc-go/frame/pkg/web"
)

// RegisterDefaultRoutes registers all routes using Web Server.
func RegisterDefaultRoutes(server *web.Server) {
	if err := server.RegisterHandler(auth.GetAuthController()); err != nil {
		panic(err)
	}
	if err := server.RegisterHandler(client.GetClientController()); err != nil {
		panic(err)
	}

	// 第三方 OAuth 授权回调端点（GET + 302 重定向，需 gin 原生路由）
	// 浏览器被第三方授权后重定向到 /auth/callback/:provider?code=xxx&state=xxx
	server.Engine().GET("/auth/callback/:provider", authcontroller.ThirdPartyCallbackHandler)
}
