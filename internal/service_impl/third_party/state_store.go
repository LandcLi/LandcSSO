package third_party

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/landc-go/log/facade"
)

const (
	// stateTTL OAuth state 有效期（10 分钟）
	stateTTL = 10 * time.Minute
	// stateRedisKeyPrefix Redis key 前缀
	stateRedisKeyPrefix = "oauth:state:"
	// stateStoreCleanupInterval 内存回退清理间隔
	stateStoreCleanupInterval = 5 * time.Minute
)

// stateEntry 内存回退存储的 state 条目
type stateEntry struct {
	provider  string
	expiresAt time.Time
}

// stateStore OAuth state 存储：优先 Redis，Redis 不可用时回退进程内存
type stateStore struct {
	mu       sync.Mutex
	fallback map[string]stateEntry
}

var defaultStateStore = &stateStore{
	fallback: make(map[string]stateEntry),
}

func init() {
	go defaultStateStore.cleanupLoop()
}

// GenerateState 生成并保存 OAuth state（绑定 provider）
func GenerateState(provider string) string {
	return defaultStateStore.GenerateState(provider)
}

// ValidateAndConsumeState 校验并消费 OAuth state（一次性）
func ValidateAndConsumeState(state, provider string) bool {
	return defaultStateStore.ValidateAndConsumeState(state, provider)
}

// GenerateState 生成随机 state 并保存（绑定 provider）
func (s *stateStore) GenerateState(provider string) string {
	state := randomState()

	if rc := config.GetRedis(); rc != nil {
		key := stateRedisKeyPrefix + state
		if err := rc.Set(context.Background(), key, provider, stateTTL).Err(); err != nil {
			facade.Errorf("保存OAuth state到Redis失败: %v", err)
		} else {
			return state
		}
	}

	// Redis 不可用，回退内存
	s.mu.Lock()
	s.fallback[state] = stateEntry{
		provider:  provider,
		expiresAt: time.Now().Add(stateTTL),
	}
	s.mu.Unlock()
	return state
}

// ValidateAndConsumeState 校验并消费 state（一次性，校验后立即删除）
func (s *stateStore) ValidateAndConsumeState(state, provider string) bool {
	if state == "" {
		return false
	}

	if rc := config.GetRedis(); rc != nil {
		key := stateRedisKeyPrefix + state
		val, err := rc.Get(context.Background(), key).Result()
		if err != nil {
			// 不存在或已过期
			return false
		}
		if val != provider {
			// provider 不匹配，删除并拒绝
			rc.Del(context.Background(), key)
			return false
		}
		rc.Del(context.Background(), key)
		return true
	}

	// 内存回退
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.fallback[state]
	if !ok {
		return false
	}
	delete(s.fallback, state)
	if entry.provider != provider {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		return false
	}
	return true
}

// cleanupLoop 定期清理过期的内存回退条目
func (s *stateStore) cleanupLoop() {
	ticker := time.NewTicker(stateStoreCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for state, entry := range s.fallback {
			if now.After(entry.expiresAt) {
				delete(s.fallback, state)
			}
		}
		s.mu.Unlock()
	}
}

// randomState 生成 URL-safe 的随机 state（32 字节 hex）
func randomState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败时使用时间戳兜底（几乎不会发生）
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b)
}
