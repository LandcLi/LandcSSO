package key

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/logger"
)

type key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

type keyServiceImpl struct {
	config config.JWTConfig
	keys   map[string]*key
}

func NewKeyServiceImpl() *keyServiceImpl {
	return &keyServiceImpl{
		keys: make(map[string]*key),
	}
}

func init() {
	if service.GetKeyService() == nil {
		service.RegisterKeyServiceImpl(NewKeyServiceImpl())
	}
}

func (s *keyServiceImpl) GenerateKey() (*service.Key, error) {
	ctx := context.Background()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Errorf(ctx, "生成RSA密钥对失败: %v", err)
		return nil, err
	}

	key := &key{
		ID:         fmt.Sprintf("key:%d", time.Now().UnixNano()),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}

	s.keys[key.ID] = key

	return &service.Key{
		ID:         key.ID,
		PrivateKey: key.PrivateKey,
		PublicKey:  key.PublicKey,
		CreatedAt:  key.CreatedAt.Unix(),
		ExpiresAt:  key.ExpiresAt.Unix(),
	}, nil
}

func (s *keyServiceImpl) GetKey(keyID string) (*service.Key, error) {
	key, exists := s.keys[keyID]
	if !exists {
		return nil, errors.New("密钥不存在")
	}

	if time.Now().After(key.ExpiresAt) {
		return nil, errors.New("密钥已过期")
	}

	return &service.Key{
		ID:         key.ID,
		PrivateKey: key.PrivateKey,
		PublicKey:  key.PublicKey,
		CreatedAt:  key.CreatedAt.Unix(),
		ExpiresAt:  key.ExpiresAt.Unix(),
	}, nil
}

func (s *keyServiceImpl) GetCurrentKey() (*service.Key, error) {
	if len(s.keys) == 0 {
		return s.GenerateKey()
	}

	for _, key := range s.keys {
		if time.Now().Before(key.ExpiresAt) {
			return &service.Key{
				ID:         key.ID,
				PrivateKey: key.PrivateKey,
				PublicKey:  key.PublicKey,
				CreatedAt:  key.CreatedAt.Unix(),
				ExpiresAt:  key.ExpiresAt.Unix(),
			}, nil
		}
	}

	return s.GenerateKey()
}

func (s *keyServiceImpl) GetPublicKeyPEM(key *service.Key) (string, error) {
	ctx := context.Background()
	publicKey, ok := key.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("无效的公钥类型")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		logger.Errorf(ctx, "编码公钥失败: %v", err)
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

func (s *keyServiceImpl) GetPrivateKeyPEM(key *service.Key) (string, error) {
	ctx := context.Background()
	privateKey, ok := key.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("无效的私钥类型")
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if privateKeyBytes == nil {
		logger.Error(ctx, "编码私钥失败")
		return "", errors.New("编码私钥失败")
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

func (s *keyServiceImpl) RevokeKey(keyID string) error {
	_, exists := s.keys[keyID]
	if !exists {
		return errors.New("密钥不存在")
	}

	delete(s.keys, keyID)

	return nil
}

func (s *keyServiceImpl) CleanExpiredKeys() {
	ctx := context.Background()
	for keyID, key := range s.keys {
		if time.Now().After(key.ExpiresAt) {
			delete(s.keys, keyID)
			logger.Infof(ctx, "清理过期密钥: %s", keyID)
		}
	}
}
