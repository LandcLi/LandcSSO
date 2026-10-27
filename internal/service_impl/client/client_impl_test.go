package client

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// 切换到项目根目录，确保 config.yaml 可以被找到
	dirs := []string{
		".",
		"..",
		"../..",
		"../../..",
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir + "/config.yaml"); err == nil {
			_ = os.Chdir(dir)
			break
		}
	}
	os.Exit(m.Run())
}

func TestGenerateClientID(t *testing.T) {
	id := GenerateClientID()
	if !strings.HasPrefix(id, "client_") {
		t.Errorf("ClientID 应以 'client_' 开头, 实际: %s", id)
	}
	if len(id) != len("client_")+8 {
		t.Errorf("ClientID 长度应为 %d, 实际 %d", len("client_")+8, len(id))
	}

	// 验证只包含允许的字符
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomPart := id[len("client_"):]
	for _, ch := range randomPart {
		if !strings.ContainsRune(charset, ch) {
			t.Errorf("ClientID 包含非法字符: %c", ch)
		}
	}
}

func TestGenerateClientSecret(t *testing.T) {
	secret := GenerateClientSecret()
	if !strings.HasPrefix(secret, "secret_") {
		t.Errorf("ClientSecret 应以 'secret_' 开头, 实际: %s", secret)
	}
	if len(secret) != len("secret_")+32 {
		t.Errorf("ClientSecret 长度应为 %d, 实际 %d", len("secret_")+32, len(secret))
	}
}
