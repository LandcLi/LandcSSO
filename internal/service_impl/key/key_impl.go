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
	"sync"
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
	mu       sync.RWMutex
	initOnce sync.Once
	keys     map[string]*key
	// fixedCfg 非空时优先于全局配置（仅供测试注入，生产代码保持 nil）
	fixedCfg *config.JWTConfig
}

// NewKeyServiceImpl 构造密钥服务。
//
// 不在构造期读写密钥文件：本实例在包 init() 中创建，此时配置尚未加载，
// 且「import 即写盘」会让任何引用本包的宿主产生意外的文件副作用。
// 密钥改为首次使用时惰性加载/生成。
func NewKeyServiceImpl() *keyServiceImpl {
	return &keyServiceImpl{
		keys: make(map[string]*key),
	}
}

// newKeyServiceWithConfig 用显式配置构造实例，避免测试依赖全局配置。
func newKeyServiceWithConfig(cfg config.JWTConfig) *keyServiceImpl {
	return &keyServiceImpl{
		keys:     make(map[string]*key),
		fixedCfg: &cfg,
	}
}

// cfg 惰性获取 JWT 配置，缺失时返回零值（调用方按「未配置」处理）。
func (s *keyServiceImpl) cfg() config.JWTConfig {
	if s.fixedCfg != nil {
		return *s.fixedCfg
	}
	if cfg := config.GetConfig(); cfg != nil {
		return cfg.JWT
	}
	return config.JWTConfig{}
}

// ensureInitialized 首次使用时加载或生成密钥，幂等。
func (s *keyServiceImpl) ensureInitialized() {
	s.initOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		// 优先从持久化文件加载密钥，保证重启后 kid 稳定（OIDC 依赖方可持续验证）
		if s.loadKeyFromFilesLocked() {
			return
		}
		k, err := s.generateKeyLocked()
		if err != nil {
			facade.Errorf("生成RSA密钥失败: %v", err)
			return
		}
		facade.Infof("已生成新的RSA密钥: %s", k.ID)
		s.saveKeyToFilesLocked(k)
	})
}

// loadKeyFromFilesLocked 从 privateKeyPath/publicKeyPath 加载 RSA 密钥对。
// 调用方需持有写锁。
func (s *keyServiceImpl) loadKeyFromFilesLocked() bool {
	cfg := s.cfg()
	if cfg.PrivateKeyPath == "" || cfg.PublicKeyPath == "" {
		return false
	}

	privPEM, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		facade.Warnf("读取私钥文件失败（将重新生成）: %v", err)
		return false
	}
	pubPEM, err := os.ReadFile(cfg.PublicKeyPath)
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

// saveKeyToFilesLocked 将密钥对持久化到文件，避免重启丢失。调用方需持有写锁。
func (s *keyServiceImpl) saveKeyToFilesLocked(k *service.Key) {
	cfg := s.cfg()
	if cfg.PrivateKeyPath == "" || cfg.PublicKeyPath == "" {
		return
	}

	if err := os.MkdirAll(filepath.Dir(cfg.PrivateKeyPath), 0700); err != nil {
		facade.Errorf("创建密钥目录失败: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(cfg.PublicKeyPath), 0700); err != nil {
		facade.Errorf("创建密钥目录失败: %v", err)
		return
	}

	if priv, err := s.GetPrivateKeyPEM(k); err == nil {
		if err := os.WriteFile(cfg.PrivateKeyPath, []byte(priv), keyFileMode); err != nil {
			facade.Errorf("保存私钥失败: %v", err)
		}
	}
	if pub, err := s.GetPublicKeyPEM(k); err == nil {
		if err := os.WriteFile(cfg.PublicKeyPath, []byte(pub), keyFileMode); err != nil {
			facade.Errorf("保存公钥失败: %v", err)
		}
	}
	facade.Infof("RSA密钥已持久化: %s -> %s", cfg.PrivateKeyPath, cfg.PublicKeyPath)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generateKeyLocked()
}

// generateKeyLocked 生成新密钥并放入内存表。调用方需持有写锁。
func (s *keyServiceImpl) generateKeyLocked() (*service.Key, error) {
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
	s.ensureInitialized()

	s.mu.RLock()
	defer s.mu.RUnlock()
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
	s.ensureInitialized()

	s.mu.RLock()
	for _, key := range s.keys {
		if time.Now().Before(key.ExpiresAt) {
			out := &service.Key{
				ID:         key.ID,
				PrivateKey: key.PrivateKey,
				PublicKey:  key.PublicKey,
				CreatedAt:  key.CreatedAt.Unix(),
				ExpiresAt:  key.ExpiresAt.Unix(),
			}
			s.mu.RUnlock()
			return out, nil
		}
	}
	s.mu.RUnlock()

	// 无可用密钥（首次或全部过期）：生成一把新的
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generateKeyLocked()
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
	s.ensureInitialized()

	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.keys[keyID]
	if !exists {
		return errors.New("密钥不存在")
	}

	delete(s.keys, keyID)

	return nil
}

func (s *keyServiceImpl) CleanExpiredKeys() {
	s.ensureInitialized()

	s.mu.Lock()
	defer s.mu.Unlock()
	for keyID, key := range s.keys {
		if time.Now().After(key.ExpiresAt) {
			delete(s.keys, keyID)
			facade.Infof("清理过期密钥: %s", keyID)
		}
	}
}
