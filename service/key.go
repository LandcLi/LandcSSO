package service

type Key struct {
	ID         string
	PrivateKey interface{}
	PublicKey  interface{}
	CreatedAt  int64
	ExpiresAt  int64
}

type keyService interface {
	GenerateKey() (*Key, error)
	GetKey(keyID string) (*Key, error)
	GetCurrentKey() (*Key, error)
	GetPublicKeyPEM(key *Key) (string, error)
	GetPrivateKeyPEM(key *Key) (string, error)
	RevokeKey(keyID string) error
	CleanExpiredKeys()
}

var keyServiceImpl keyService

func RegisterKeyServiceImpl(impl keyService) {
	keyServiceImpl = impl
}

func GetKeyService() keyService {
	return keyServiceImpl
}
