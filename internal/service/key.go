package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/LandcLi/LandcSSO/pkg/logger"
)

// KeyService 密钥服务
type KeyService struct {
	config config.JWTConfig
	keys   map[string]*Key
}

// Key 密钥结构
type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// NewKeyService 创建密钥服务实例
func NewKeyService(cfg config.JWTConfig) *KeyService {
	return &KeyService{
		config: cfg,
		keys:   make(map[string]*Key),
	}
}

// GenerateKey 生成RSA密钥对
func (s *KeyService) GenerateKey() (*Key, error) {
	ctx := context.Background()
	// 生成RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Errorf(ctx, "生成RSA密钥对失败: %v", err)
		return nil, err
	}

	// 创建密钥
	key := &Key{
		ID:         fmt.Sprintf("key:%d", time.Now().UnixNano()),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour), // 30天过期
	}

	// 存储密钥
	s.keys[key.ID] = key

	return key, nil
}

// GetKey 获取密钥
func (s *KeyService) GetKey(keyID string) (*Key, error) {
	// 查找密钥
	key, exists := s.keys[keyID]
	if !exists {
		return nil, errors.New("密钥不存在")
	}

	// 检查密钥是否过期
	if time.Now().After(key.ExpiresAt) {
		return nil, errors.New("密钥已过期")
	}

	return key, nil
}

// GetCurrentKey 获取当前使用的密钥
func (s *KeyService) GetCurrentKey() (*Key, error) {
	// 如果没有密钥，生成一个新的
	if len(s.keys) == 0 {
		return s.GenerateKey()
	}

	// 查找未过期的密钥
	for _, key := range s.keys {
		if time.Now().Before(key.ExpiresAt) {
			return key, nil
		}
	}

	// 所有密钥都已过期，生成新的
	return s.GenerateKey()
}

// GetPublicKeyPEM 获取公钥PEM格式
func (s *KeyService) GetPublicKeyPEM(key *Key) (string, error) {
	ctx := context.Background()
	// 编码公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key.PublicKey)
	if err != nil {
		logger.Errorf(ctx, "编码公钥失败: %v", err)
		return "", err
	}

	// 创建PEM块
	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// 编码PEM
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

// GetPrivateKeyPEM 获取私钥PEM格式
func (s *KeyService) GetPrivateKeyPEM(key *Key) (string, error) {
	ctx := context.Background()
	// 编码私钥
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key.PrivateKey)
	if privateKeyBytes == nil {
		logger.Error(ctx, "编码私钥失败")
		return "", errors.New("编码私钥失败")
	}

	// 创建PEM块
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// 编码PEM
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

// RevokeKey 撤销密钥
func (s *KeyService) RevokeKey(keyID string) error {
	// 查找密钥
	_, exists := s.keys[keyID]
	if !exists {
		return errors.New("密钥不存在")
	}

	// 删除密钥
	delete(s.keys, keyID)

	return nil
}

// CleanExpiredKeys 清理过期密钥
func (s *KeyService) CleanExpiredKeys() {
	ctx := context.Background()
	for keyID, key := range s.keys {
		if time.Now().After(key.ExpiresAt) {
			delete(s.keys, keyID)
			logger.Infof(ctx, "清理过期密钥: %s", keyID)
		}
	}
}
