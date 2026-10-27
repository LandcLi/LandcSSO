package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/LandcLi/landc-go/log/facade"
	"gorm.io/gorm"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/utility/config"
)

// 令牌撤销的判定与缓存。
//
// 背景：ValidateToken 此前只验签名 + IP + 设备指纹，**从不检查数据库里的
// revoked 标记**。后果是撤销、登出、并发会话踢下线全部「假失效」——
// 标记写了，但令牌在过期前（默认 30 分钟）仍然畅通无阻。
//
// 设计原则：数据库是唯一真相源，Redis 只是可选的加速层。
//   - Redis 未配置 / 连不上 / 报错 → 全部跳过，直接查库，正确性不受影响；
//   - Redis 只用于「快速拒绝」：命中撤销标记时不必查库；
//     但「未命中」不能当作「未撤销」，必须查库确认，否则撤销后缓存未失效会误放行。

// revokedCachePrefix Redis 中撤销标记的 key 前缀。
const revokedCachePrefix = "sso:revoked:"

// revokedCacheMinTTL 撤销标记的最短缓存时间。
// 令牌剩余寿命可能很短（快过期），给一个下限避免缓存刚写入就失效。
const revokedCacheMinTTL = 60 * time.Second

// tokenCacheKey 生成撤销缓存的 key。
//
// 用 SHA-256 摘要而不是 JWT 原文：令牌有 700+ 字符，直接做 key 既占内存
// 又会让令牌出现在 Redis 慢日志 / MONITOR 输出里。
func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return revokedCachePrefix + hex.EncodeToString(sum[:])
}

// cacheIsRevoked 查询缓存中的撤销标记。任何异常都当作「缓存无信息」返回 false。
func (s *authServiceImpl) cacheIsRevoked(ctx context.Context, token string) bool {
	rc := config.GetRedis()
	if rc == nil {
		return false
	}
	// 查询失败（含 Redis 挂掉）视为未命中，交给数据库判定
	n, err := rc.Exists(ctx, tokenCacheKey(token)).Result()
	if err != nil {
		return false
	}
	return n > 0
}

// markRevokedInCache 把撤销标记写入缓存。
//
// 失败只记日志：数据库已经改了，缓存只是加速手段。
// ttl 由调用方按令牌剩余寿命给出，保证缓存不会比令牌活得更久。
func (s *authServiceImpl) markRevokedInCache(ctx context.Context, token string, ttl time.Duration) {
	rc := config.GetRedis()
	if rc == nil {
		return
	}
	if ttl < revokedCacheMinTTL {
		ttl = revokedCacheMinTTL
	}
	if err := rc.Set(ctx, tokenCacheKey(token), "1", ttl).Err(); err != nil {
		facade.Warnf("写入撤销缓存失败（不影响撤销结果，数据库已生效）: %v", err)
	}
}

// revokeCacheTTL 按令牌剩余寿命算缓存时长。
func revokeCacheTTL(exp time.Time) time.Duration {
	ttl := time.Until(exp)
	if ttl < revokedCacheMinTTL {
		return revokedCacheMinTTL
	}
	return ttl
}

// isAccessTokenRevoked 判断一个 access token 当前是否不可用。
//
// 返回 (true, nil) 表示应当拒绝；(false, nil) 表示可用；
// (_, err) 表示无法确认（数据库不可用），调用方应按失败关闭处理。
//
// 为什么「查不到记录」也判定为撤销：tokens 表里没有这条 access token，
// 说明它要么从未签发过，要么已被后台清理（清理条件是 refresh 过期或已撤销）。
// 两种情况都不该继续放行。
func (s *authServiceImpl) isAccessTokenRevoked(ctx context.Context, tokenString string) (bool, error) {
	// 1. 缓存快速拒绝
	if s.cacheIsRevoked(ctx, tokenString) {
		return true, nil
	}

	// 2. 数据库为准
	rec, err := dao.GetTokenDao().FindByAccessToken(tokenString)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return true, nil
		}
		return false, err
	}
	if rec.Revoked {
		// 回填缓存，减少后续对已撤销令牌的查库
		s.markRevokedInCache(ctx, tokenString, revokeCacheTTL(rec.ExpiresAt))
		return true, nil
	}
	if !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt) {
		return true, nil
	}
	return false, nil
}

// revokeByTokenString 按令牌原文撤销单条记录，并写入撤销缓存。
func (s *authServiceImpl) revokeByTokenString(ctx context.Context, tokenString string) error {
	token, err := dao.GetTokenDao().FindByAccessToken(tokenString)
	if err != nil {
		return err
	}

	token.Revoked = true
	if _, err := dao.GetTokenDao().Update(token); err != nil {
		return err
	}
	s.markRevokedInCache(ctx, tokenString, revokeCacheTTL(token.ExpiresAt))
	return nil
}
