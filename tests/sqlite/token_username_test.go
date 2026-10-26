package sqlite_test

import (
	"context"
	"testing"

	frameauth "github.com/LandcLi/landc-go/frame/pkg/auth"

	"github.com/LandcLi/LandcSSO/service"
)

// TestLoginTokenCarriesUsername 验证签发的令牌里带用户名。
//
// 历史缺陷：generateAccessToken / generateRefreshToken / generateTempToken 都写死了
// GenerateTokenWithOpts(userID, "", ...)，第二个参数（username）恒为空串。
// 根因是 LandcUserManager 的 LoginResponse 不返回用户名，SSO 无从得知。
// 后果：下游拿到 userID 有效、username 为空的令牌，按用户名做的逻辑全部失效。
//
// 本用例直接调 service 层，不依赖 LUM 的真实用户，只验证「传进来的 username
// 确实写进了 token claims」。
func TestLoginTokenCarriesUsername(t *testing.T) {
	setupSQLiteEnv(t)

	const (
		userID   = uint(42)
		username = "alice"
	)
	ctx := context.Background()
	svc := service.GetAuthService()

	resp, err := svc.Login(ctx, userID, username, false, false, "127.0.0.1", "fp-test", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("令牌为空: access=%q refresh=%q", resp.AccessToken, resp.RefreshToken)
	}

	// 1. access token 的 username
	accessClaims, err := frameauth.ParseToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("解析 access token: %v", err)
	}
	if accessClaims.Username != username {
		t.Errorf("access token username = %q, want %q", accessClaims.Username, username)
	}
	if accessClaims.UserID != userID {
		t.Errorf("access token user_id = %d, want %d", accessClaims.UserID, userID)
	}

	// 2. refresh token 的 username（刷新时据此保持新令牌一致）
	refreshClaims, err := frameauth.ParseToken(resp.RefreshToken)
	if err != nil {
		t.Fatalf("解析 refresh token: %v", err)
	}
	if refreshClaims.Username != username {
		t.Errorf("refresh token username = %q, want %q", refreshClaims.Username, username)
	}
}

// TestRefreshTokenKeepsUsername 验证刷新后的新令牌仍带用户名。
//
// 刷新是高频路径，如果新令牌把 username 丢了，同一个用户前后两个令牌就会不一致
// （前者有用户名、后者没有），下游按用户名做的判断会出现难以复现的差异。
func TestRefreshTokenKeepsUsername(t *testing.T) {
	setupSQLiteEnv(t)

	const (
		userID   = uint(43)
		username = "bob"
	)
	ctx := context.Background()
	svc := service.GetAuthService()

	first, err := svc.Login(ctx, userID, username, false, false, "127.0.0.1", "fp-test", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// 用首个 refresh token 换新令牌。刷新按 RFC 6749 §6 要求客户端认证，
	// 这里用测试配置 seed 的客户端（见 smoke_test.go 的 seed 段）。
	second, err := svc.RefreshToken(ctx, first.RefreshToken,
		"sqlite-smoke-client", "sqlite-smoke-secret", "127.0.0.1", "fp-test")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}

	claims, err := frameauth.ParseToken(second.AccessToken)
	if err != nil {
		t.Fatalf("解析新 access token: %v", err)
	}
	if claims.Username != username {
		t.Errorf("刷新后 access token username = %q, want %q（用户名在刷新时丢了）", claims.Username, username)
	}
	if claims.UserID != userID {
		t.Errorf("刷新后 user_id = %d, want %d", claims.UserID, userID)
	}
}
