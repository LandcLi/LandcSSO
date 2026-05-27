package tests

import (
	"testing"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
)

func TestKeyService_GenerateKey(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 创建密钥服务
	keyService := service.NewKeyService(cfg.JWT)

	// 测试生成密钥
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

func TestKeyService_GetKey(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 创建密钥服务
	keyService := service.NewKeyService(cfg.JWT)

	// 生成密钥
	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	// 获取密钥
	retrievedKey, err := keyService.GetKey(key.ID)
	if err != nil {
		t.Fatalf("GetKey() 失败: %v", err)
	}

	if retrievedKey.ID != key.ID {
		t.Errorf("KeyID 期望 '%s', 实际 '%s'", key.ID, retrievedKey.ID)
	}
}

func TestKeyService_GetCurrentKey(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 创建密钥服务
	keyService := service.NewKeyService(cfg.JWT)

	// 获取当前密钥
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
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 创建密钥服务
	keyService := service.NewKeyService(cfg.JWT)

	// 生成密钥
	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	// 获取公钥PEM
	pem, err := keyService.GetPublicKeyPEM(key)
	if err != nil {
		t.Fatalf("GetPublicKeyPEM() 失败: %v", err)
	}

	if pem == "" {
		t.Error("PublicKey PEM 为空")
	}
}

func TestKeyService_GetPrivateKeyPEM(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 创建密钥服务
	keyService := service.NewKeyService(cfg.JWT)

	// 生成密钥
	key, err := keyService.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() 失败: %v", err)
	}

	// 获取私钥PEM
	pem, err := keyService.GetPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("GetPrivateKeyPEM() 失败: %v", err)
	}

	if pem == "" {
		t.Error("PrivateKey PEM 为空")
	}
}

func TestKeyService_RevokeKey(t *testing.T) {
	// 加载配置
	cfg, err := config.LoadConfig("../config.yml")
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 创建密钥服务
	keyService := service.NewKeyService(cfg.JWT)

	// 生成密钥
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
