package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/landc-go/log/facade"
)

const (
	// defaultKeyTTL 密钥有效期（30 天）
	defaultKeyTTL = 30 * 24 * time.Hour
	// keyFileMode 密钥文件权限（仅所有者可读写）
	keyFileMode = 0600
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
	s := &keyServiceImpl{
		keys: make(map[string]*key),
	}
	if cfg := config.GetConfig(); cfg != nil {
		s.config = cfg.JWT
	}

	// 优先从持久化文件加载密钥，保证重启后 kid 稳定（OIDC 依赖方可持续验证）
	if !s.loadKeyFromFiles() {
		if k, err := s.GenerateKey(); err != nil {
			facade.Errorf("生成RSA密钥失败: %v", err)
		} else {
			facade.Infof("已生成新的RSA密钥: %s", k.ID)
			s.saveKeyToFiles(k)
		}
	}
	return s
}

// loadKeyFromFiles 从 privateKeyPath/publicKeyPath 加载 RSA 密钥对
func (s *keyServiceImpl) loadKeyFromFiles() bool {
	if s.config.PrivateKeyPath == "" || s.config.PublicKeyPath == "" {
		return false
	}

	privPEM, err := os.ReadFile(s.config.PrivateKeyPath)
	if err != nil {
		facade.Warnf("读取私钥文件失败（将重新生成）: %v", err)
		return false
	}
	pubPEM, err := os.ReadFile(s.config.PublicKeyPath)
	if err != nil {
		facade.Warnf("读取公钥文件失败（将重新生成）: %v", err)
		return false
	}

	privateKey, err := parsePrivateKey(privPEM)
	if err != nil {
		facade.Errorf("解析私钥失败（将重新生成）: %v", err)
		return false
	}

	// 校验公钥文件与私钥是否匹配
	expectedPub, err := parsePublicKey(pubPEM)
	if err != nil || !expectedPub.Equal(&privateKey.PublicKey) {
		facade.Warnf("公钥与私钥不匹配（将重新生成）")
		return false
	}

	now := time.Now()
	k := &key{
		ID:         keyIDFromPublicKey(&privateKey.PublicKey),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  now,
		ExpiresAt:  now.Add(defaultKeyTTL),
	}
	s.keys[k.ID] = k
	facade.Infof("已从文件加载RSA密钥: %s", k.ID)
	return true
}

// saveKeyToFiles 将密钥对持久化到文件，避免重启丢失
func (s *keyServiceImpl) saveKeyToFiles(k *service.Key) {
	if s.config.PrivateKeyPath == "" || s.config.PublicKeyPath == "" {
		return
	}

	if err := os.MkdirAll(filepath.Dir(s.config.PrivateKeyPath), 0700); err != nil {
		facade.Errorf("创建密钥目录失败: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.config.PublicKeyPath), 0700); err != nil {
		facade.Errorf("创建密钥目录失败: %v", err)
		return
	}

	if priv, err := s.GetPrivateKeyPEM(k); err == nil {
		if err := os.WriteFile(s.config.PrivateKeyPath, []byte(priv), keyFileMode); err != nil {
			facade.Errorf("保存私钥失败: %v", err)
		}
	}
	if pub, err := s.GetPublicKeyPEM(k); err == nil {
		if err := os.WriteFile(s.config.PublicKeyPath, []byte(pub), keyFileMode); err != nil {
			facade.Errorf("保存公钥失败: %v", err)
		}
	}
	facade.Infof("RSA密钥已持久化: %s -> %s", s.config.PrivateKeyPath, s.config.PublicKeyPath)
}

// parsePrivateKey 解析 PEM 私钥（兼容 PKCS1 / PKCS8）
func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("无效的PEM数据")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("非RSA私钥")
	}
	return rsaKey, nil
}

// parsePublicKey 解析 PEM 公钥
func parsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("无效的PEM数据")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("非RSA公钥")
	}
	return rsaKey, nil
}

// keyIDFromPublicKey 基于公钥指纹生成稳定密钥 ID
func keyIDFromPublicKey(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Sprintf("key:%d", time.Now().UnixNano())
	}
	hash := sha256.Sum256(der)
	return "key:" + hex.EncodeToString(hash[:8])
}

func init() {
	if service.GetKeyService() == nil {
		service.RegisterKeyServiceImpl(NewKeyServiceImpl())
	}
}

func (s *keyServiceImpl) GenerateKey() (*service.Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		facade.Errorf("生成RSA密钥对失败: %v", err)
		return nil, err
	}

	now := time.Now()
	key := &key{
		ID:         keyIDFromPublicKey(&privateKey.PublicKey),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  now,
		ExpiresAt:  now.Add(defaultKeyTTL),
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
	publicKey, ok := key.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("无效的公钥类型")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		facade.Errorf("编码公钥失败: %v", err)
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
	privateKey, ok := key.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("无效的私钥类型")
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if privateKeyBytes == nil {
		facade.Error("编码私钥失败")
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
	for keyID, key := range s.keys {
		if time.Now().After(key.ExpiresAt) {
			delete(s.keys, keyID)
			facade.Infof("清理过期密钥: %s", keyID)
		}
	}
}
