package sqlite_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	frameauth "github.com/LandcLi/landc-go/frame/pkg/auth"
	framecache "github.com/LandcLi/landc-go/frame/pkg/cache"
	frameconfig "github.com/LandcLi/landc-go/frame/pkg/config"
	framedb "github.com/LandcLi/landc-go/frame/pkg/db"

	"github.com/gin-gonic/gin"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/serverlib"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/security"
)

const seedClientID = "sqlite-smoke-client"
const seedClientSecret = "sqlite-smoke-secret"

// configTemplate 以 SQLite 为唯一外部依赖，验证「开箱即用」能力。
const configTemplate = `
server:
  addr: "127.0.0.1"
  port: 0
database:
  driver: "sqlite"
  dsn: "%s"
  auto_migrate: true
redis:
  addr: ""
user_manager:
  mode: "local"
seed:
  enabled: true
  clientId: "sqlite-smoke-client"
  clientSecret: "sqlite-smoke-secret"
  redirectUris:
    - "http://localhost:9999/callback"
  scope: "openid profile email"
jwt:
  signingMethod: "HS256"
  secret: "sqlite-smoke-test-secret-key-at-least-32-chars"
  issuer: "landc-sso-test"
  accessTokenExpiry: 1800
  refreshTokenExpiry: 86400
log:
  provider: "console"
  level: "error"
  format: "text"
  outputPath: "stdout"
`

// setupSQLiteEnv 用临时目录中的 SQLite 完成一次完整 bootstrap，返回配置路径。
func setupSQLiteEnv(t *testing.T) string {
	t.Helper()

	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data", "sso.db")
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(configTemplate, filepath.ToSlash(dbPath))), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// 框架侧：配置 → DB → 缓存 → JWT（与 cmd bootstrap 一致）
	if err := frameconfig.InitGlobalConfigWithPath(configPath); err != nil {
		t.Fatalf("init framework config: %v", err)
	}
	t.Cleanup(func() {
		_ = framedb.Close()
		_ = framecache.Close()
	})
	if err := framedb.InitGlobalDBWithDefault(); err != nil {
		t.Fatalf("init db: %v", err)
	}
	if err := framecache.InitGlobalCacheWithDefault(); err != nil {
		t.Fatalf("init cache: %v", err)
	}
	frameauth.InitFromConfig(frameconfig.GetConfig())

	// SSO 侧：自有配置 + 建表 + 种子
	if err := config.Init(configPath); err != nil {
		t.Fatalf("init sso config: %v", err)
	}
	if err := serverlib.EnsureSchema(); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	if err := serverlib.Seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return configPath
}

// TestSQLiteSchemaCreated 验证 auto_migrate 建出了 SSO 自身的全部表。
func TestSQLiteSchemaCreated(t *testing.T) {
	setupSQLiteEnv(t)

	migrator := framedb.GetDB().Migrator()
	for _, m := range serverlib.Models() {
		if !migrator.HasTable(m) {
			t.Errorf("table missing after EnsureSchema: %T", m)
		}
	}
}

// TestSQLiteSeedClient 验证示例客户端被写入且密钥为哈希存储、可正确校验。
func TestSQLiteSeedClient(t *testing.T) {
	setupSQLiteEnv(t)

	client, err := dao.GetClientDao().FindByClientID(seedClientID)
	if err != nil {
		t.Fatalf("seed client not found: %v", err)
	}
	if client.ClientSecret == seedClientSecret {
		t.Error("client secret must be hashed, not stored in plaintext")
	}
	if !security.VerifySecret(client.ClientSecret, seedClientSecret) {
		t.Error("hashed secret should verify against the configured plaintext")
	}
	if client.Status != 1 {
		t.Errorf("seed client status = %d, want 1", client.Status)
	}

	// 幂等：重复 Seed 不应产生第二条
	if err := serverlib.Seed(); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	var count int64
	if err := framedb.GetDB().Model(&model.Client{}).Where("client_id = ?", seedClientID).Count(&count).Error; err != nil {
		t.Fatalf("count clients: %v", err)
	}
	if count != 1 {
		t.Errorf("seed client count = %d, want 1 (Seed must be idempotent)", count)
	}
}

// TestHTTPClientCredentials 走完整 HTTP 链路（中间件 → 路由 → 客户端校验 → 签发 JWT），
// 验证 SQLite 环境下 token 端点可用。
func TestHTTPClientCredentials(t *testing.T) {
	setupSQLiteEnv(t)

	server := httptest.NewServer(buildRouter(t))
	defer server.Close()

	body, _ := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     seedClientID,
		"client_secret": seedClientSecret,
	})
	resp, err := http.Post(server.URL+"/auth/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post token: %v", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	// 框架统一包装响应：{code, message, data}，token 字段在 data 内
	var payload struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint status = %d, raw=%s", resp.StatusCode, string(rawBody))
	}
	if payload.Data.AccessToken == "" {
		t.Fatalf("expected access_token in data, raw=%s", string(rawBody))
	}
	if payload.Data.TokenType == "" {
		t.Error("expected token_type in response")
	}

	// 错误密钥应被拒绝
	badBody, _ := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     seedClientID,
		"client_secret": "wrong-secret",
	})
	badResp, err := http.Post(server.URL+"/auth/token", "application/json", bytes.NewReader(badBody))
	if err != nil {
		t.Fatalf("post token with bad secret: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode == http.StatusOK {
		t.Error("token endpoint must reject wrong client secret")
	}
}

// TestUserManagerLocalMode 验证进程内模式：LUM 实现被装配进 DI，可完成注册。
func TestUserManagerLocalMode(t *testing.T) {
	setupSQLiteEnv(t)
	buildRouter(t) // 触发 serverlib 装配（含 user_manager=local 的 Install）

	ctx := t.Context()
	userSvc := userService()

	resp, err := userSvc.Register(ctx, registerRequest("sso_local_user", "Passw0rd!"))
	if err != nil {
		t.Fatalf("register via in-process user manager: %v", err)
	}
	if resp.UserID == 0 {
		t.Fatal("expected non-zero user id")
	}

	// 用户表应落在同一个 SQLite 库中（进程内共享连接）
	if !framedb.GetDB().Migrator().HasTable("users") {
		t.Error("users table should exist in the shared sqlite database")
	}
}
