package serverlib

import (
	"sync"
	"time"

	"github.com/LandcLi/landc-go/log/facade"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/utility/config"
)

// 过期令牌/授权码的后台物理清理。
//
// tokens 与 authorization_codes 两张表此前只有写入、从不清理：每次 login /
// refresh / 授权码签发都 INSERT 一条，长期运行会无限增长。这里用一个后台 ticker
// 周期性物理删除已过期（refresh 已过期）或已撤销的令牌，以及过期授权码。

var (
	cleanupOnce sync.Once
	cleanupStop chan struct{}
)

// startTokenCleanup 启动后台清理任务（幂等，只启动一次）。
//
// 遵循 state_store.go 的既有模式：ticker + 无显式关闭（随进程退出）。
// 但这里额外维护 cleanupStop，供测试与优雅停机时停止。
func startTokenCleanup(cfg config.TokenCleanupConfig) {
	if !cfg.Enabled {
		return
	}
	cleanupOnce.Do(func() {
		cleanupStop = make(chan struct{})
		go cleanupLoop(cfg.Interval(), cleanupStop)
	})
}

// 说明：这里不提供 stopTokenCleanup。
//
// 清理任务是无状态的单条 SQL，进程退出时 goroutine 随之结束，被中断也不会
// 留下不一致数据（下次启动会再跑一次）。此前写过一个 stopTokenCleanup 的
// 停机钩子，但全仓库没有任何调用方 —— 属于只写不用的死代码，已移除。

func cleanupLoop(interval time.Duration, stop chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 启动即执行一次，避免「刚部署要等一个 interval 才生效」。
	runTokenCleanup()

	for {
		select {
		case <-ticker.C:
			runTokenCleanup()
		case <-stop:
			return
		}
	}
}

// runTokenCleanup 执行一轮清理：过期/已撤销令牌 + 过期授权码。
// 单独失败互不影响，只记录日志不中断后台任务。
func runTokenCleanup() {
	if n, err := dao.GetTokenDao().DeleteExpiredTokens(time.Now()); err != nil {
		facade.Errorf("清理过期令牌失败: %v", err)
	} else if n > 0 {
		facade.Infof("清理过期/已撤销令牌 %d 条", n)
	}

	if err := dao.GetTokenDao().DeleteExpiredCodes(); err != nil {
		facade.Errorf("清理过期授权码失败: %v", err)
	}
}
