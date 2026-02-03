package token

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type tokenDaoImpl struct {
	db          *gorm.DB
	redisClient redis.UniversalClient
}

func NewTokenDaoImpl() *tokenDaoImpl {
	return &tokenDaoImpl{
		db:          config.GetDB(),
		redisClient: config.GetRedis(),
	}
}

func init() {
	if dao.GetTokenDao() == nil {
		dao.RegisterTokenDaoImpl(NewTokenDaoImpl())
	}
}

func (r *tokenDaoImpl) Create(token *model.Token) (*model.Token, error) {
	err := r.db.Create(token).Error
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (r *tokenDaoImpl) FindByID(id uint) (*model.Token, error) {
	var token model.Token
	err := r.db.First(&token, id).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *tokenDaoImpl) FindByAccessToken(accessToken string) (*model.Token, error) {
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("token:access:%s", accessToken)
		data, err := r.redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var token model.Token
			if err := json.Unmarshal(data, &token); err == nil {
				return &token, nil
			}
		}
	}

	var token model.Token
	err := r.db.Where("access_token = ?", accessToken).First(&token).Error
	if err != nil {
		return nil, err
	}

	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("token:access:%s", accessToken)
		data, err := json.Marshal(token)
		if err == nil {
			expiration := time.Until(token.ExpiresAt) / 2
			if expiration > 0 {
				r.redisClient.Set(context.Background(), cacheKey, data, expiration)
			}
		}
	}

	return &token, nil
}

func (r *tokenDaoImpl) FindByRefreshToken(refreshToken string) (*model.Token, error) {
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("token:refresh:%s", refreshToken)
		data, err := r.redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var token model.Token
			if err := json.Unmarshal(data, &token); err == nil {
				return &token, nil
			}
		}
	}

	var token model.Token
	err := r.db.Where("refresh_token = ?", refreshToken).First(&token).Error
	if err != nil {
		return nil, err
	}

	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("token:refresh:%s", refreshToken)
		data, err := json.Marshal(token)
		if err == nil {
			expiration := time.Until(token.RefreshExpiresAt) / 2
			if expiration > 0 {
				r.redisClient.Set(context.Background(), cacheKey, data, expiration)
			}
		}
	}

	return &token, nil
}

func (r *tokenDaoImpl) Update(token *model.Token) (*model.Token, error) {
	err := r.db.Save(token).Error
	if err != nil {
		return nil, err
	}

	if r.redisClient != nil {
		if token.AccessToken != "" {
			cacheKey := fmt.Sprintf("token:access:%s", token.AccessToken)
			data, err := json.Marshal(token)
			if err == nil {
				expiration := time.Until(token.ExpiresAt) / 2
				if expiration > 0 {
					r.redisClient.Set(context.Background(), cacheKey, data, expiration)
				}
			}
		}

		if token.RefreshToken != "" {
			cacheKey := fmt.Sprintf("token:refresh:%s", token.RefreshToken)
			data, err := json.Marshal(token)
			if err == nil {
				expiration := time.Until(token.RefreshExpiresAt) / 2
				if expiration > 0 {
					r.redisClient.Set(context.Background(), cacheKey, data, expiration)
				}
			}
		}
	}

	return token, nil
}

func (r *tokenDaoImpl) Delete(id uint) error {
	var token model.Token
	if err := r.db.First(&token, id).Error; err == nil {
		if r.redisClient != nil {
			if token.AccessToken != "" {
				cacheKey := fmt.Sprintf("token:access:%s", token.AccessToken)
				r.redisClient.Del(context.Background(), cacheKey)
			}
			if token.RefreshToken != "" {
				cacheKey := fmt.Sprintf("token:refresh:%s", token.RefreshToken)
				r.redisClient.Del(context.Background(), cacheKey)
			}
		}
	}

	return r.db.Delete(&model.Token{}, id).Error
}

func (r *tokenDaoImpl) FindByUserID(userID uint) ([]*model.Token, error) {
	var tokens []*model.Token
	err := r.db.Where("user_id = ? AND revoked = ?", userID, false).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *tokenDaoImpl) RevokeByUserID(userID uint) error {
	return r.db.Model(&model.Token{}).Where("user_id = ? AND revoked = ?", userID, false).Update("revoked", true).Error
}

func (r *tokenDaoImpl) CreateAuthorizationCode(code *model.AuthorizationCode) (*model.AuthorizationCode, error) {
	err := r.db.Create(code).Error
	if err != nil {
		return nil, err
	}
	return code, nil
}

func (r *tokenDaoImpl) FindByCode(code string) (*model.AuthorizationCode, error) {
	var authCode model.AuthorizationCode
	err := r.db.Where("code = ?", code).First(&authCode).Error
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

func (r *tokenDaoImpl) MarkAsUsed(id uint) error {
	return r.db.Model(&model.AuthorizationCode{}).Where("id = ?", id).Update("used", true).Error
}

func (r *tokenDaoImpl) DeleteExpiredCodes() error {
	return r.db.Where("expires_at < NOW()").Delete(&model.AuthorizationCode{}).Error
}

func (r *tokenDaoImpl) GetRedisClient() redis.UniversalClient {
	return r.redisClient
}
