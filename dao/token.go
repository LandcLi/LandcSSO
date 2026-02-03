package dao

import (
	"github.com/LandcLi/LandcSSO/model"
	"github.com/go-redis/redis/v8"
)

type tokenDao interface {
	Create(token *model.Token) (*model.Token, error)
	FindByID(id uint) (*model.Token, error)
	FindByAccessToken(accessToken string) (*model.Token, error)
	FindByRefreshToken(refreshToken string) (*model.Token, error)
	Update(token *model.Token) (*model.Token, error)
	Delete(id uint) error
	FindByUserID(userID uint) ([]*model.Token, error)
	RevokeByUserID(userID uint) error
	CreateAuthorizationCode(code *model.AuthorizationCode) (*model.AuthorizationCode, error)
	FindByCode(code string) (*model.AuthorizationCode, error)
	MarkAsUsed(id uint) error
	DeleteExpiredCodes() error
	GetRedisClient() redis.UniversalClient
}

var tokenDaoImpl tokenDao

func RegisterTokenDaoImpl(impl tokenDao) {
	tokenDaoImpl = impl
}

func GetTokenDao() tokenDao {
	return tokenDaoImpl
}
