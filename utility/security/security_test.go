package security

import "testing"

func TestHashAndVerifySecret(t *testing.T) {
	secret := "my-super-secret-value-12345"
	hash, err := HashSecret(secret)
	if err != nil {
		t.Fatalf("HashSecret() 失败: %v", err)
	}

	if hash == secret {
		t.Error("哈希不应等于明文")
	}
	if len(hash) < 50 {
		t.Errorf("bcrypt 哈希长度异常: %d", len(hash))
	}

	if !VerifySecret(hash, secret) {
		t.Error("VerifySecret() 应通过正确密钥")
	}
	if VerifySecret(hash, "wrong-secret") {
		t.Error("VerifySecret() 应拒绝错误密钥")
	}
}

func TestVerifySecretLegacyPlaintext(t *testing.T) {
	// 兼容历史明文数据
	if !VerifySecret("legacy-plain-secret", "legacy-plain-secret") {
		t.Error("VerifySecret() 应兼容旧明文数据")
	}
	if VerifySecret("legacy-plain-secret", "wrong") {
		t.Error("VerifySecret() 应拒绝错误的旧明文")
	}
}

func TestVerifySecretEmpty(t *testing.T) {
	if VerifySecret("", "anything") {
		t.Error("空存储值应拒绝")
	}
	if VerifySecret("anything", "") {
		t.Error("空输入值应拒绝")
	}
	if VerifySecret("", "") {
		t.Error("双空值应拒绝")
	}
}
