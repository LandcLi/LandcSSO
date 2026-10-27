package sqlite_test

import (
	"context"
	"testing"
	"time"

	framedb "github.com/LandcLi/landc-go/frame/pkg/db"

	frameauth "github.com/LandcLi/landc-go/frame/pkg/auth"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
)

// 令牌撤销链路的守门测试。
//
// 历史缺陷：ValidateToken 只验签名 + IP + 设备指纹，从不检查数据库里的
// revoked 标记。于是：
//   - /auth/revoke-token 撤销后令牌仍可用；
//   - /auth/logout 登出后令牌仍可用；
//   - maxConcurrentSessions 踢下线不生效（它靠标记 revoked 实现）。
// 三者共用同一条底层路径，此前一条测试都没有，所以缺陷能一直潜伏。
//
// 这些用例同时覆盖「无 Redis 环境」：测试配置不接 Redis，
// config.GetRedis() 返回 nil，验证了「Redis 不可用时靠数据库仍然正确」。

// issueToken 登录并返回令牌响应。
func issueToken(t *testing.T, userID uint, username string) *tokenPair {
	t.Helper()
	resp, err := service.GetAuthService().Login(
		context.Background(), userID, username, false, false, "127.0.0.1", "fp-revoke", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return &tokenPair{access: resp.AccessToken, refresh: resp.RefreshToken}
}

type tokenPair struct {
	access  string
	refresh string
}

// TestValidTokenAccepted 基线：未撤销的令牌必须通过校验。
// 如果这条挂了，说明撤销检查误杀了正常令牌。
func TestValidTokenAccepted(t *testing.T) {
	setupSQLiteEnv(t)

	p := issueToken(t, 501, "valid-user")
	if _, err := service.GetAuthService().ValidateToken(
		context.Background(), p.access, "127.0.0.1", "fp-revoke"); err != nil {
		t.Fatalf("未撤销的令牌应通过校验，实际失败: %v", err)
	}
}

// TestRevokedTokenRejected 撤销后令牌必须立刻失效。
func TestRevokedTokenRejected(t *testing.T) {
	setupSQLiteEnv(t)

	ctx := context.Background()
	svc := service.GetAuthService()

	p := issueToken(t, 502, "revoke-user")

	// 撤销前可用
	if _, err := svc.ValidateToken(ctx, p.access, "127.0.0.1", "fp-revoke"); err != nil {
		t.Fatalf("撤销前应可用: %v", err)
	}

	if err := svc.RevokeToken(ctx, p.access); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// 撤销后必须被拒 —— 这是本用例的核心断言
	if _, err := svc.ValidateToken(ctx, p.access, "127.0.0.1", "fp-revoke"); err == nil {
		t.Fatal("令牌已撤销，校验却通过了（撤销形同虚设）")
	}
}

// TestLogoutInvalidatesTokens 登出后该用户的所有令牌必须失效。
func TestLogoutInvalidatesTokens(t *testing.T) {
	setupSQLiteEnv(t)

	ctx := context.Background()
	svc := service.GetAuthService()

	p := issueToken(t, 503, "logout-user")

	if err := svc.Logout(ctx, 503, "127.0.0.1", "fp-revoke", "test-agent"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := svc.ValidateToken(ctx, p.access, "127.0.0.1", "fp-revoke"); err == nil {
		t.Fatal("登出后令牌仍通过校验（登出形同虚设）")
	}
}

// TestConcurrentSessionKickInvalidatesOldest 超出并发上限时最旧的令牌必须失效。
//
// 这条覆盖的是「假踢下线」：checkConcurrentSessions 会标记 revoked，
// 但若 ValidateToken 不查库，被踢的人其实还在线。
func TestConcurrentSessionKickInvalidatesOldest(t *testing.T) {
	setupSQLiteEnv(t)

	ctx := context.Background()
	svc := service.GetAuthService()

	const userID = uint(504)
	// 测试配置 MaxConcurrentSessions = 5，签发 6 个令牌，
	// 第 6 次登录会把最旧的那个标记撤销。
	var first *tokenPair
	var last *tokenPair
	for i := 0; i < 6; i++ {
		p := issueToken(t, userID, "kick-user")
		if i == 0 {
			first = p
		}
		last = p
	}

	if _, err := svc.ValidateToken(ctx, first.access, "127.0.0.1", "fp-revoke"); err == nil {
		t.Error("超出并发上限后，最旧的令牌应被踢下线，实际仍可用")
	}

	// 诊断：打印库中该用户全部令牌的状态
	var all []model.Token
	if err := framedb.GetDB().Where("user_id = ?", userID).Order("id").Find(&all).Error; err == nil {
		for _, tk := range all {
			t.Logf("id=%d created=%s revoked=%v", tk.ID, tk.CreatedAt.Format("15:04:05.000000"), tk.Revoked)
		}
	}

	// 诊断：直接查 DAO
	if rec, err := dao.GetTokenDao().FindByAccessToken(last.access); err != nil {
		t.Logf("FindByAccessToken(last) 失败: %v", err)
	} else {
		t.Logf("FindByAccessToken(last) => id=%d revoked=%v", rec.ID, rec.Revoked)
	}

	if _, err := svc.ValidateToken(ctx, last.access, "127.0.0.1", "fp-revoke"); err != nil {
		t.Errorf("最新签发的令牌应可用，实际失败: %v", err)
	}
}

// TestUnknownAccessTokenRejected 数据库里查不到的 access token 必须被拒。
//
// 令牌记录会被后台清理（refresh 过期或已撤销），清理后它在库里不存在。
// 这种「幽灵令牌」不该因为签名仍然有效就被放行。
func TestUnknownAccessTokenRejected(t *testing.T) {
	setupSQLiteEnv(t)

	// 先用一个用户签出令牌，再直接把它对应的记录删掉，模拟被清理。
	p := issueToken(t, 505, "ghost-user")

	// 用一个未登记过的用户签发（不落库的方式拿不到，改为篡改）：
	// 这里直接用「签发后删除记录」来构造幽灵令牌。
	// 通过 DAO 删除需要 id，改为校验一个从未签发的随机格式令牌不可行（签名必失败），
	// 因此改用 TempToken 之外的路径：撤销并清理。
	ctx := context.Background()
	svc := service.GetAuthService()
	if err := svc.RevokeToken(ctx, p.access); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	// 撤销后执行一次清理，把记录物理删除
	if _, err := dao.GetTokenDao().DeleteExpiredTokens(time.Now()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if _, err := svc.ValidateToken(ctx, p.access, "127.0.0.1", "fp-revoke"); err == nil {
		t.Fatal("记录已被清理的令牌不应通过校验")
	}
}

// TestRevokeUnknownTokenIsIdempotent RFC 7009 §2.2：撤销不存在的令牌也应返回成功。
//
// 如果返回「令牌不存在」，调用方就能通过响应差异判断某个令牌是否有效，
// 等于提供一个令牌有效性探针。
//
// 实际触发场景：新设备登录下发的是临时令牌（不落 tokens 表），
// 客户端拿它来撤销时会走到这里。
func TestRevokeUnknownTokenIsIdempotent(t *testing.T) {
	setupSQLiteEnv(t)

	svc := service.GetAuthService()
	ctx := context.Background()

	// 一个格式合法但从未签发的令牌
	unknown, err := frameauth.GenerateTokenWithOpts(999, "ghost", frameauth.GenerateTokenOption{
		TokenType:  "access",
		ExpireTime: time.Hour,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if err := svc.RevokeToken(ctx, unknown); err != nil {
		t.Errorf("撤销未登记的令牌应视为成功（RFC 7009），实际返回错误: %v", err)
	}
}
