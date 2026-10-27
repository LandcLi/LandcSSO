package auth

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/LandcLi/landc-go/log/facade"

	userapi "github.com/LandcLi/LandcUserManager/api/user"
	userv1api "github.com/LandcLi/LandcUserManager/api/user/v1"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
)

// jsonKeyError OIDC 错误响应体的键名，多处复用故提取为常量。
const jsonKeyError = "error"

// 本文件实现 OIDC 规范要求的三个只读端点。
//
// 为什么用 gin 原生路由而不是 meta.Meta 声明：
//   - 三者都是无请求体的 GET，meta 那套是围绕「请求结构体 + 反射」设计的；
//   - userinfo 要读 Authorization 头（已由 AuthRequired 中间件解析并放进
//     gin.Context），原生 handler 拿上下文最直接。
//
// 历史状态：README 写着 curl /.well-known/openid-configuration、
// docs/api.md 写着 /auth/userinfo，GetJWKS 也早就实现好了 ——
// 但三者的路由一个都没注册。任何标准 OIDC 客户端（Grafana、GitLab、
// ArgoCD、Keycloak 联邦）第一步拉 discovery 就 404，接入直接失败。

// DefaultScopes 是 discovery 对外声明的 scope 列表。
var DefaultScopes = []string{"openid", "profile", "email", "phone"}

// DiscoveryHandler 返回 OIDC Discovery 文档。
// 必须匿名可访问：客户端在拿到任何凭据之前就要拉它。
func DiscoveryHandler(c *gin.Context) {
	cfg := config.GetConfig()
	if cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{jsonKeyError: "配置未初始化"})
		return
	}

	issuer := strings.TrimRight(cfg.JWT.Issuer, "/")
	if !isAbsoluteURL(issuer) {
		// OIDC 规范要求 issuer 是绝对 URL，且必须等于 ID Token 的 iss。
		// 配置里写 "sso-server" 这类裸名字时，拼出来的 authorization_endpoint
		// 会变成 "sso-server/auth/authorize" 这种相对路径 —— 标准客户端
		// （Grafana / GitLab / ArgoCD / Keycloak 联邦）拉完 discovery 直接失败。
		// 这里用请求来源兜底保证端点可用，同时告警提示改配置（改完后 JWT 的
		// iss claim 也会跟着变成 URL，两者自动一致）。
		fallback := requestBaseURL(c)
		facade.Warnf("jwt.issuer %q 不是绝对 URL，OIDC discovery 已改用请求来源 %q；"+
			"请把配置里的 jwt.issuer 改为绝对 URL（如 http://localhost:8080）以与令牌 iss 保持一致",
			issuer, fallback)
		issuer = fallback
	}

	doc := gin.H{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/auth/authorize",
		"token_endpoint":         issuer + "/auth/token",
		"userinfo_endpoint":      issuer + "/auth/userinfo",
		"jwks_uri":               issuer + "/auth/jwks",
		"introspection_endpoint": issuer + "/auth/introspect",
		"revocation_endpoint":    issuer + "/auth/revoke-token",
		"end_session_endpoint":   issuer + "/auth/logout",

		"scopes_supported":         DefaultScopes,
		"response_types_supported": []string{"code"},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
			"password",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{signingAlg(cfg)},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "preferred_username", "name", "email", "phone_number",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	}

	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, doc)
}

// JWKSHandler 返回签名公钥集合（jwks_uri）。
// 必须匿名可访问：验证 ID Token 签名的客户端不会带我方令牌。
func JWKSHandler(c *gin.Context) {
	// 对称签名算法（HS256/HS384/HS512）用的是共享密钥，无法也不应公开公钥。
	// 此前这里无条件返回 RSA 公钥，而默认配置是 HS256 —— discovery 声称 HS256、
	// jwks 却给 RS256，会让按 jwks 判断算法的客户端做出错误假设。
	// 按规范：对称算法返回空 keys 集合。
	if alg := signingAlg(config.GetConfig()); strings.HasPrefix(strings.ToUpper(alg), "HS") {
		c.Header("Cache-Control", "public, max-age=3600")
		c.JSON(http.StatusOK, gin.H{"keys": []any{}})
		return
	}

	svc := service.GetAuthService()
	if svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{jsonKeyError: "认证服务未初始化"})
		return
	}

	resp, err := svc.GetJWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{jsonKeyError: err.Error()})
		return
	}

	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, resp)
}

// isAbsoluteURL 判断是否为带 scheme 的绝对 URL。
func isAbsoluteURL(s string) bool {
	i := strings.Index(s, "://")
	return i > 0 && !strings.ContainsAny(s[:i], "/ ")
}

// UserInfoHandler 返回当前 access_token 对应的用户信息（OIDC /userinfo）。
//
// 依赖 AuthRequired 中间件：它在放行前已校验令牌并把 UserID 放进 gin.Context。
// 账号字段来自 LandcUserManager —— 用户的邮箱、昵称、头像都在那边，
// SSO 只保管认证与令牌，不重复存一份用户档案。
func UserInfoHandler(c *gin.Context) {
	raw, ok := c.Get("UserID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{jsonKeyError: "未认证"})
		return
	}
	userID, ok := raw.(uint)
	if !ok || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{jsonKeyError: "未认证"})
		return
	}

	ctx := c.Request.Context()
	profile, err := userapi.GetUserController().GetUserInfo(ctx, &userv1api.GetUserInfoRequest{UserID: userID})
	if err != nil {
		// 令牌有效但取不到档案：属于服务间问题，不能伪装成 401 让客户端去重新登录。
		c.JSON(http.StatusBadGateway, gin.H{jsonKeyError: "无法获取用户信息"})
		return
	}

	// sub 必须是字符串（OIDC 规范），且与 ID Token 里的 sub 一致。
	info := gin.H{
		"sub":                formatSubject(userID),
		"preferred_username": profile.Username,
		"name":               firstNonEmpty(profile.Nickname, profile.Username),
	}
	if profile.Email != "" {
		info["email"] = profile.Email
		info["email_verified"] = false
	}
	if profile.Phone != "" {
		info["phone_number"] = profile.Phone
	}
	if profile.Avatar != "" {
		info["picture"] = profile.Avatar
	}

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, info)
}

// formatSubject 生成 OIDC 的 sub（十进制 userID 字符串）。
// 必须稳定：客户端会把 sub 当作本地用户的唯一标识长期保存。
func formatSubject(userID uint) string {
	return strconv.FormatUint(uint64(userID), 10)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// signingAlg 取配置的签名算法，缺省按 HS256（与服务端签发实现保持一致）。
func signingAlg(cfg *config.Config) string {
	if cfg != nil && cfg.JWT.SigningMethod != "" {
		return cfg.JWT.SigningMethod
	}
	return "HS256"
}

// requestBaseURL 用请求本身的 scheme+host 兜底 issuer。
func requestBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + c.Request.Host
}

// 确保 json 包被使用（gin.H 序列化由 gin 完成，这里显式保留给调试输出）。
