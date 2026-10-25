package api

import (
	"github.com/LandcLi/landc-go/frame/pkg/web"

	"github.com/LandcLi/LandcSSO/api/auth"
	"github.com/LandcLi/LandcSSO/api/client"
	authcontroller "github.com/LandcLi/LandcSSO/internal/controller/auth"
)

// RegisterDefaultRoutes 注册 SSO 的全部 HTTP 路由。
// 控制器路由由 meta.Meta 标签声明，框架自动生成；OAuth 回调需要浏览器 302，
// 因此单独以 gin 原生路由注册。
func RegisterDefaultRoutes(server *web.Server) error {
	if err := server.RegisterHandler(auth.GetAuthController()); err != nil {
		return err
	}
	if err := server.RegisterHandler(client.GetClientController()); err != nil {
		return err
	}

	// 第三方 OAuth 授权回调端点（GET + 302 重定向，需 gin 原生路由）
	// 浏览器被第三方授权后重定向到 /auth/callback/:provider?code=xxx&state=xxx
	server.Engine().GET("/auth/callback/:provider", authcontroller.ThirdPartyCallbackHandler)
	return nil
}
