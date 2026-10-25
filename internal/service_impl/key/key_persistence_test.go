package key

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LandcLi/LandcSSO/utility/config"
)

// TestKeyPersistence 验证 RSA 密钥持久化：生成后保存到文件，重新加载后 kid 与公钥一致
func TestKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	s := newKeyServiceWithConfig(config.JWTConfig{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
	})

	// 生成并保存
	k, err := s.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}
	s.mu.Lock(); s.saveKeyToFilesLocked(k); s.mu.Unlock()

	// 验证文件已创建
	if _, err := os.Stat(privPath); err != nil {
		t.Fatalf("私钥文件未生成: %v", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("公钥文件未生成: %v", err)
	}

	// 模拟重启：用同一路径构造新实例加载
	s2 := newKeyServiceWithConfig(config.JWTConfig{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
	})
	if !s2.loadKeyFromFilesLocked() {
		t.Fatal("loadKeyFromFiles() 失败")
	}

	current, err := s2.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey() 失败: %v", err)
	}

	// 密钥 ID 必须稳定（OIDC 依赖方依赖 kid 一致性）
	if current.ID != k.ID {
		t.Errorf("重启后 kid 变化: 期望 %s, 实际 %s", k.ID, current.ID)
	}

	// 私钥必须可正常导出（说明加载的密钥对有效）
	if _, err := s2.GetPrivateKeyPEM(current); err != nil {
		t.Errorf("加载的私钥无效: %v", err)
	}
}

// TestLoadKeyFromFilesNotExist 无密钥文件时返回 false，触发重新生成
func TestLoadKeyFromFilesNotExist(t *testing.T) {
	dir := t.TempDir()
	s := newKeyServiceWithConfig(config.JWTConfig{
		PrivateKeyPath: filepath.Join(dir, "no-private.pem"),
		PublicKeyPath:  filepath.Join(dir, "no-public.pem"),
	})
	if s.loadKeyFromFilesLocked() {
		t.Error("文件不存在时应返回 false")
	}
}
