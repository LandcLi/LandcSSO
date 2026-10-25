package serverlib

import (
	"fmt"

	framedb "github.com/LandcLi/landc-go/frame/pkg/db"

	"github.com/LandcLi/LandcSSO/model"
)

// Models 返回 LandcSSO 负责的全部持久化模型。
// 用户数据由 LandcUserManager 负责，本系统只持有 OAuth2/OIDC 自身的数据。
func Models() []interface{} {
	return []interface{}{
		&model.Client{},
		&model.Token{},
		&model.AuthorizationCode{},
		&model.AuditEvent{},
		&model.MonitorMetric{},
		&model.AnomalyEvent{},
	}
}

// EnsureSchema 按配置决定是否自动建表/补列。
//
// 受框架配置 database.auto_migrate 控制：
//   - SQLite / 开发测试环境建议开启，开箱即用；
//   - MySQL 生产环境建议关闭，由 sqls/init.sql 或版本化迁移接管。
func EnsureSchema() error {
	if err := framedb.AutoMigrateIfEnabled(Models()...); err != nil {
		return fmt.Errorf("serverlib: migrate schema: %w", err)
	}
	return nil
}
