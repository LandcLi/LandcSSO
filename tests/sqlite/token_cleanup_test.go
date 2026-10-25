package sqlite_test

import (
	"testing"
	"time"

	framedb "github.com/LandcLi/landc-go/frame/pkg/db"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
)

// TestDeleteExpiredTokensCleansOnlyUseless 验证物理清理只删「refresh 已过期」或「已撤销」的令牌。
//
// 历史缺陷：tokens 表只有写入、从不清理，每次 login/refresh 都 INSERT 一条，
// 长期运行无限增长。本用例锁定清理语义：
//   - refresh 未过期的（即使 access 已过期）必须保留 —— 否则 refresh 链断裂；
//   - refresh 已过期的、已撤销的必须删除。
func TestDeleteExpiredTokensCleansOnlyUseless(t *testing.T) {
	setupSQLiteEnv(t)

	db := framedb.GetDB()
	now := time.Now()

	// 场景 1：refresh 未过期（access 已过期但仍可刷新）→ 保留
	stillRefreshable := &model.Token{
		UserID:           1,
		AccessToken:      "tok-still-refreshable",
		RefreshToken:     "rt-still-refreshable",
		ExpiresAt:        now.Add(-time.Hour), // access 已过期
		RefreshExpiresAt: now.Add(time.Hour),  // refresh 仍有效
		ClientID:         "c1",
		Revoked:          false,
	}
	// 场景 2：refresh 已过期 → 删除
	fullyExpired := &model.Token{
		UserID:           1,
		AccessToken:      "tok-fully-expired",
		RefreshToken:     "rt-fully-expired",
		ExpiresAt:        now.Add(-2 * time.Hour),
		RefreshExpiresAt: now.Add(-time.Hour), // refresh 已过期
		ClientID:         "c1",
		Revoked:          false,
	}
	// 场景 3：已撤销（refresh 仍有效）→ 删除
	revoked := &model.Token{
		UserID:           1,
		AccessToken:      "tok-revoked",
		RefreshToken:     "rt-revoked",
		ExpiresAt:        now.Add(time.Hour),
		RefreshExpiresAt: now.Add(time.Hour),
		ClientID:         "c1",
		Revoked:          true,
	}

	for _, tok := range []*model.Token{stillRefreshable, fullyExpired, revoked} {
		if err := db.Create(tok).Error; err != nil {
			t.Fatalf("create token: %v", err)
		}
	}

	deleted, err := dao.GetTokenDao().DeleteExpiredTokens(now)
	if err != nil {
		t.Fatalf("DeleteExpiredTokens: %v", err)
	}
	if deleted != 2 {
		t.Errorf("删除条数 = %d, want 2（refresh 过期 + 已撤销）", deleted)
	}

	// stillRefreshable 必须还在
	if _, err := dao.GetTokenDao().FindByRefreshToken("rt-still-refreshable"); err != nil {
		t.Errorf("refresh 未过期的令牌不应被删: %v", err)
	}
	// 另外两条必须已删
	if _, err := dao.GetTokenDao().FindByRefreshToken("rt-fully-expired"); err == nil {
		t.Error("refresh 已过期的令牌应被删除")
	}
	if _, err := dao.GetTokenDao().FindByRefreshToken("rt-revoked"); err == nil {
		t.Error("已撤销的令牌应被删除")
	}
}

// TestDeleteExpiredTokensKeepsActiveTokens 验证正常活跃令牌不受清理影响。
func TestDeleteExpiredTokensKeepsActiveTokens(t *testing.T) {
	setupSQLiteEnv(t)

	db := framedb.GetDB()
	now := time.Now()

	active := &model.Token{
		UserID:           2,
		AccessToken:      "tok-active",
		RefreshToken:     "rt-active",
		ExpiresAt:        now.Add(time.Hour),
		RefreshExpiresAt: now.Add(24 * time.Hour),
		ClientID:         "c1",
		Revoked:          false,
	}
	if err := db.Create(active).Error; err != nil {
		t.Fatalf("create active token: %v", err)
	}

	if deleted, err := dao.GetTokenDao().DeleteExpiredTokens(now); err != nil {
		t.Fatalf("DeleteExpiredTokens: %v", err)
	} else if deleted != 0 {
		t.Errorf("活跃令牌不应被删，实际删除 %d 条", deleted)
	}

	if _, err := dao.GetTokenDao().FindByAccessToken("tok-active"); err != nil {
		t.Errorf("活跃令牌应保留: %v", err)
	}
}
