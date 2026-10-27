package sqlite_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LandcLi/LandcSSO/service"
)

// decodeFlat 断言响应是「扁平 JSON」，不做 {code,message,data} 包装。
//
// OIDC 客户端按标准解析 discovery / jwks / userinfo，多套一层信封就解析失败。
// 这里显式检查一次，防止以后有人给这些路由挂上统一响应中间件。
func decodeFlat(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("响应不是合法 JSON: %v raw=%s", err, string(raw))
	}
	if _, wrapped := doc["code"]; wrapped {
		t.Fatalf("OIDC 端点必须返回扁平 JSON，实际被包了信封: %s", string(raw))
	}
	return doc
}

// TestOIDCDiscoveryEndpoint 验证 /.well-known/openid-configuration 可匿名访问，
// 且声明了客户端真正需要的端点。
//
// 历史状态：README 写着这个地址能用，代码里根本没有这条路由。
// 任何标准 OIDC 客户端接入的第一步就是拉它，404 等于直接不可用。
func TestOIDCDiscoveryEndpoint(t *testing.T) {
	setupSQLiteEnv(t)
	srv := httptest.NewServer(buildRouter(t))
	defer srv.Close()

	// 不带任何凭据
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get discovery: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200, raw=%s", resp.StatusCode, string(raw))
	}

	doc := decodeFlat(t, raw)

	// 必备字段
	for _, key := range []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
	} {
		v, ok := doc[key].(string)
		if !ok || v == "" {
			t.Errorf("discovery 缺少字段 %q, raw=%s", key, string(raw))
		}
	}

	// issuer 与配置一致，且必须是绝对 URL（OIDC 规范硬要求）。
	// 写成裸名字（如 "sso-server"）时端点会退化成相对路径，
	// Grafana / GitLab / ArgoCD 等标准客户端拉完 discovery 直接接入失败。
	issuer, _ := doc["issuer"].(string)
	if issuer != "https://sso.test.local" {
		t.Errorf("issuer = %v, want https://sso.test.local", doc["issuer"])
	}
	if !strings.Contains(issuer, "://") {
		t.Errorf("issuer 必须是绝对 URL，实际 %q", issuer)
	}
	// 所有 *_endpoint / jwks_uri 也必须是绝对 URL
	for _, key := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "introspection_endpoint", "revocation_endpoint",
	} {
		if v, ok := doc[key].(string); ok && !strings.HasPrefix(v, "http") {
			t.Errorf("%s 不是绝对 URL: %q", key, v)
		}
	}

	// 声明的端点必须真的存在（否则客户端拿到一个 404 地址）。
	// token 是 POST，其余是 GET —— 方法用错时要区分 404（路由不存在）与 400（参数不对）。
	type probe struct {
		key  string
		meth string
	}
	for _, p := range []probe{
		{"userinfo_endpoint", http.MethodGet},
		{"jwks_uri", http.MethodGet},
		{"token_endpoint", http.MethodPost},
	} {
		u, _ := doc[p.key].(string)
		path := u
		if i := strings.Index(u, "/auth/"); i >= 0 {
			path = u[i:]
		}

		req, _ := http.NewRequest(p.meth, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", p.key, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("discovery 声明的 %s (%s %s) 返回 404", p.key, p.meth, path)
		}
	}
}

// TestOIDCJWKSEndpoint 验证 jwks_uri 可匿名访问。
// 验证 ID Token 签名的客户端会直接拉它，不能要求带 token。
func TestOIDCJWKSEndpoint(t *testing.T) {
	setupSQLiteEnv(t)
	srv := httptest.NewServer(buildRouter(t))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/auth/jwks")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200, raw=%s", resp.StatusCode, string(raw))
	}

	doc := decodeFlat(t, raw)
	if _, ok := doc["keys"]; !ok {
		t.Errorf("jwks 响应缺少 keys 字段, raw=%s", string(raw))
	}
}

// TestOIDCUserInfoEndpoint 验证 /auth/userinfo：
// 带有效令牌返回 sub/用户名，不带令牌返回 401。
func TestOIDCUserInfoEndpoint(t *testing.T) {
	setupSQLiteEnv(t)
	srv := httptest.NewServer(buildRouter(t))
	defer srv.Close()

	ctx := context.Background()
	const (
		username = "oidc_userinfo_user"
		password = "Passw0rd!"
		deviceFP = "sso-sqlite-smoke"
	)

	reg, err := userService().Register(ctx, registerRequest(username, password))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// 1. 无令牌 → 401
	noAuth, err := http.Get(srv.URL + "/auth/userinfo")
	if err != nil {
		t.Fatalf("get userinfo without token: %v", err)
	}
	noAuth.Body.Close()
	if noAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("无令牌访问 userinfo 状态码 = %d, want 401", noAuth.StatusCode)
	}

	// 2. 有效令牌 → 200 + 用户信息
	//
	// 注意令牌必须由 SSO 自己签发：/auth/userinfo 走 AuthRequired →
	// ValidateToken，后者会校验 tokens 表里的撤销状态。LUM 注册返回的令牌
	// 虽然因为共享 secret 能通过签名验证，但它不在 SSO 的 tokens 表里，
	// 按「未知令牌一律拒绝」的策略会被挡下 —— 这是刻意为之：
	// OIDC 端点只认本系统签发的令牌。
	tokenResp, err := service.GetAuthService().Login(
		ctx, reg.UserID, username, false, false, "127.0.0.1", deviceFP, "oidc-test")
	if err != nil {
		t.Fatalf("sso login: %v", err)
	}
	ssoToken := tokenResp.AccessToken

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+ssoToken)
	req.Header.Set("X-Device-Fingerprint", deviceFP) // 令牌绑定设备指纹

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get userinfo: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d, want 200, raw=%s", resp.StatusCode, string(raw))
	}

	doc := decodeFlat(t, raw)

	wantSub := itoaUint(reg.UserID)
	if got, _ := doc["sub"].(string); got != wantSub {
		t.Errorf("sub = %v, want %q（必须与令牌主体一致）", doc["sub"], wantSub)
	}
	if got, _ := doc["preferred_username"].(string); got != username {
		t.Errorf("preferred_username = %v, want %q", doc["preferred_username"], username)
	}

	// 3. 伪造令牌 → 401
	badReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/auth/userinfo", nil)
	badReq.Header.Set("Authorization", "Bearer not-a-real-token")
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("get userinfo with bad token: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("伪造令牌状态码 = %d, want 401", badResp.StatusCode)
	}
}

func itoaUint(v uint) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
