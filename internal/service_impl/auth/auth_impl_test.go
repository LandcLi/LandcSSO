package service

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

func TestGenerateRandomString(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	lengths := []int{8, 16, 32, 64}
	for _, length := range lengths {
		result := GenerateRandomString(length)
		if len(result) != length {
			t.Errorf("GenerateRandomString(%d) 期望长度 %d, 实际 %d", length, length, len(result))
		}
		for _, ch := range result {
			if !strings.ContainsRune(charset, ch) {
				t.Errorf("GenerateRandomString(%d) 包含非法字符: %c", length, ch)
			}
		}
	}
}

func TestGenerateRandomStringUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result := GenerateRandomString(32)
		if seen[result] {
			t.Errorf("GenerateRandomString 产生重复结果: %s", result)
		}
		seen[result] = true
	}
}

// TestIsPrivateURL 验证 SSRF 防护
func TestIsPrivateURL(t *testing.T) {
	private := []string{
		"http://localhost:8080/callback",
		"http://127.0.0.1:3000/callback",
		"http://10.0.0.1/logout",
		"http://172.16.0.1/logout",
		"http://192.168.1.1/logout",
		"http://169.254.169.254/metadata",
		"http://myapp.internal/logout",
		"http://service.local/logout",
		"::1",
		"http://0.0.0.0/x",
		"not-a-valid-url",
	}
	for _, u := range private {
		if !isPrivateURL(u) {
			t.Errorf("isPrivateURL(%q) 应返回 true", u)
		}
	}

	public := []string{
		"https://example.com/logout",
		"https://api.github.com/logout",
		"http://8.8.8.8/logout",
	}
	for _, u := range public {
		if isPrivateURL(u) {
			t.Errorf("isPrivateURL(%q) 应返回 false", u)
		}
	}
}
