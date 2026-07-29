package key

import (
	"strings"
	"testing"
)

func TestKeyService_GenerateKey(t *testing.T) {
	keyService := NewKeyServiceImpl()

	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	if key.ID == "" {
		t.Error("KeyID 为空")
	}

	if key.PrivateKey == nil {
		t.Error("PrivateKey 为空")
	}

	if key.PublicKey == nil {
		t.Error("PublicKey 为空")
	}
}

func TestKeyService_GetCurrentKey(t *testing.T) {
	keyService := NewKeyServiceImpl()

	key, err := keyService.GetCurrentKey()
	if err != nil {
		t.Fatalf("GetCurrentKey() 失败: %v", err)
	}

	if key.ID == "" {
		t.Error("KeyID 为空")
	}

	if key.PrivateKey == nil {
		t.Error("PrivateKey 为空")
	}

	if key.PublicKey == nil {
		t.Error("PublicKey 为空")
	}
}

func TestKeyService_GetPublicKeyPEM(t *testing.T) {
	keyService := NewKeyServiceImpl()

	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	pem, err := keyService.GetPublicKeyPEM(key)
	if err != nil {
		t.Fatalf("GetPublicKeyPEM() 失败: %v", err)
	}

	if pem == "" {
		t.Error("PublicKey PEM 为空")
	}

	if !strings.HasPrefix(pem, "-----BEGIN RSA PUBLIC KEY-----") {
		t.Error("PEM 格式不正确")
	}
}

func TestKeyService_GetPrivateKeyPEM(t *testing.T) {
	keyService := NewKeyServiceImpl()

	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	pem, err := keyService.GetPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("GetPrivateKeyPEM() 失败: %v", err)
	}

	if pem == "" {
		t.Error("PrivateKey PEM 为空")
	}

	if !strings.HasPrefix(pem, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("PEM 格式不正确")
	}
}

func TestKeyService_RevokeKey(t *testing.T) {
	keyService := NewKeyServiceImpl()

	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	// 撤销密钥
	err = keyService.RevokeKey(key.ID)
	if err != nil {
		t.Fatalf("RevokeKey() 失败: %v", err)
	}

	// 尝试获取已撤销的密钥
	_, err = keyService.GetKey(key.ID)
	if err == nil {
		t.Error("GetKey() 应该失败，因为密钥已撤销")
	}
}

func TestKeyService_GetKeyNotFound(t *testing.T) {
	keyService := NewKeyServiceImpl()

	_, err := keyService.GetKey("non_existent_key")
	if err == nil {
		t.Error("GetKey() 应该失败，因为密钥不存在")
	}
}
