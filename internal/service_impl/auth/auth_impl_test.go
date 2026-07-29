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
			os.Chdir(dir)
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
