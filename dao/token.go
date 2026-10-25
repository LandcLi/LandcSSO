package dao

import (
	"time"

	"github.com/LandcLi/LandcSSO/model"
	"github.com/redis/go-redis/v9"
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
	// DeleteExpiredTokens 物理删除已无用的令牌记录：
	//   - refresh 令牌已过期（access 过期但 refresh 未过期时仍可刷新，不能删）；
	//   - 或已被撤销（revoked = true，无论是否过期）。
	// 返回删除条数。用于后台定时清理，避免 tokens 表随 login/refresh 无限增长。
	DeleteExpiredTokens(now time.Time) (int64, error)
	GetRedisClient() redis.UniversalClient
}

var tokenDaoImpl tokenDao

func RegisterTokenDaoImpl(impl tokenDao) {
	tokenDaoImpl = impl
}

func GetTokenDao() tokenDao {
	return tokenDaoImpl
}
