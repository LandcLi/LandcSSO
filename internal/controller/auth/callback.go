package auth

import (
	"net/http"
	"strings"

	thirdparty "github.com/LandcLi/LandcSSO/internal/service_impl/third_party"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	userapi "github.com/LandcLi/LandcUserManager/api/user"
	userv1api "github.com/LandcLi/LandcUserManager/api/user/v1"
	"github.com/LandcLi/landc-go/log/facade"
	"github.com/gin-gonic/gin"
)

// ThirdPartyCallbackHandler 处理第三方 OAuth 授权回调（GET /auth/callback/:provider）。
//
// 浏览器被第三方（GitHub 等）授权后 302 重定向到此处，携带 code + state：
//  1. 校验 state（防 CSRF，一次性）
//  2. 用 code 换 access_token / refresh_token
//  3. 调 LUM 完成用户认证/关联（LUM 只负责认证，不签发 token）
//  4. SSO 自行签发 access_token / refresh_token（与密码登录口径一致，可被
//     introspect / jwks / refresh-token 等标准 OIDC 端点校验）
//  5. 302 重定向回前端（token 通过 URL fragment 传递，避免进入服务器日志）
func ThirdPartyCallbackHandler(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")

	frontendURL := callbackFrontendURL()
	redirectWith := func(params string) {
		c.Redirect(http.StatusFound, frontendURL+"#"+params)
	}

	// 1. 校验 CSRF state（服务端生成，必须原样回传，一次性）
	if !thirdparty.ValidateAndConsumeState(state, provider) {
		facade.Warnf("第三方回调state校验失败: provider=%s", provider)
		redirectWith("error=invalid_state")
		return
	}

	// 2. 获取适配器并换 token
	adapter, ok := service.GetThirdPartyAdapter(provider)
	if !ok {
		facade.Warnf("第三方回调适配器未找到: provider=%s", provider)
		redirectWith("error=unsupported_provider")
		return
	}
	accessToken, refreshToken, openId, err := adapter.FetchAccessTokenAndRefreshToken(
		c.Request.Context(), code, providerRedirectURI(provider))
	if err != nil {
		facade.Errorf("第三方回调换token失败: provider=%s err=%v", provider, err)
		redirectWith("error=token_exchange_failed")
		return
	}

	// 3. 调 LUM 完成用户认证（THIRD_PARTY，token 换用户信息由 LUM FetchUserInfo 承担）
	//    LUM 只负责认证，token 签发权在 SSO（见步骤 4）
	deviceFingerprint := c.GetHeader("X-Device-Fingerprint")
	if deviceFingerprint == "" {
		deviceFingerprint = strings.ToLower(provider) + "-callback"
	}
	loginResp, err := userapi.GetUserController().Login(c.Request.Context(), &userv1api.LoginRequest{
		Identifier:        openId,
		VerifyType:        strings.ToUpper(provider),
		AuthCode:          openId,
		AuthType:          "THIRD_PARTY",
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		IP:                c.ClientIP(),
		DeviceFingerprint: deviceFingerprint,
		UserAgent:         c.GetHeader("User-Agent"),
	})
	if err != nil {
		facade.Errorf("第三方回调LUM登录失败: provider=%s err=%v", provider, err)
		redirectWith("error=login_failed")
		return
	}

	// 4. SSO 自行签发 token（与 /auth/login 的 PASSWORD/THIRD_PARTY 流程同口径），
	//    确保返回的 token 可被 SSO 的 introspect / jwks / refresh-token 端点识别
	tokenResp, err := service.GetAuthService().Login(c.Request.Context(),
		loginResp.UserID, loginResp.Username, loginResp.DifferentLocation, loginResp.IsNewDevice,
		c.ClientIP(), deviceFingerprint, c.GetHeader("User-Agent"))
	if err != nil {
		facade.Errorf("第三方回调SSO签发token失败: provider=%s err=%v", provider, err)
		redirectWith("error=token_issue_failed")
		return
	}

	// 5. 302 回前端，SSO 签发的 token 通过 URL fragment 传递
	redirectWith("token=" + tokenResp.AccessToken + "&refresh_token=" + tokenResp.RefreshToken)
}

// callbackFrontendURL 返回第三方回调成功后重定向的前端地址
func callbackFrontendURL() string {
	if cfg := config.GetConfig(); cfg != nil && cfg.Frontend.CallbackURL != "" {
		return cfg.Frontend.CallbackURL
	}
	return "http://localhost:3000"
}

// providerRedirectURI 返回配置中注册的第三方回调地址（与 GitHub 注册的 callback 一致）
func providerRedirectURI(provider string) string {
	if cfg := config.GetConfig(); cfg != nil && cfg.ThirdParty != nil {
		if m, ok := cfg.ThirdParty[strings.ToLower(provider)]; ok {
			if uri, ok := m["redirect_uri"].(string); ok {
				return uri
			}
		}
	}
	return ""
}
