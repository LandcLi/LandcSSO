package security

import (
	"crypto/subtle"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashSecret 对客户端密钥进行 bcrypt 哈希
func HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifySecret 验证客户端密钥。
// 优先使用 bcrypt 恒定时间比较；为兼容历史明文数据，旧数据使用常量时间比较。
func VerifySecret(stored, provided string) bool {
	if stored == "" || provided == "" {
		return false
	}
	// bcrypt 哈希比较本身是恒定时间安全的
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil
	}
	// 旧版明文兼容：使用恒定时间比较，避免时序侧信道
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}
