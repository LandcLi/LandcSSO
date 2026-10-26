package token

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type tokenDaoImpl struct{}

func NewTokenDaoImpl() *tokenDaoImpl {
	return &tokenDaoImpl{}
}

func (r *tokenDaoImpl) getDB() *gorm.DB {
	return config.GetDB()
}

func (r *tokenDaoImpl) getRedis() redis.UniversalClient {
	rc := config.GetRedis()
	if rc == nil {
		return nil
	}
	return rc
}

func init() {
	if dao.GetTokenDao() == nil {
		dao.RegisterTokenDaoImpl(NewTokenDaoImpl())
	}
}

func (r *tokenDaoImpl) Create(token *model.Token) (*model.Token, error) {
	err := r.getDB().Create(token).Error
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (r *tokenDaoImpl) FindByID(id uint) (*model.Token, error) {
	var token model.Token
	err := r.getDB().First(&token, id).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *tokenDaoImpl) FindByAccessToken(accessToken string) (*model.Token, error) {
	rc := r.getRedis()
	if rc != nil {
		cacheKey := fmt.Sprintf("token:access:%s", accessToken)
		data, err := rc.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var token model.Token
			if err := json.Unmarshal(data, &token); err == nil {
				return &token, nil
			}
		}
	}

	var token model.Token
	err := r.getDB().Where("access_token = ?", accessToken).First(&token).Error
	if err != nil {
		return nil, err
	}

	if rc != nil {
		cacheKey := fmt.Sprintf("token:access:%s", accessToken)
		data, err := json.Marshal(token)
		if err == nil {
			expiration := time.Until(token.ExpiresAt) / 2
			if expiration > 0 {
				rc.Set(context.Background(), cacheKey, data, expiration)
			}
		}
	}

	return &token, nil
}

func (r *tokenDaoImpl) FindByRefreshToken(refreshToken string) (*model.Token, error) {
	rc := r.getRedis()
	if rc != nil {
		cacheKey := fmt.Sprintf("token:refresh:%s", refreshToken)
		data, err := rc.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var token model.Token
			if err := json.Unmarshal(data, &token); err == nil {
				return &token, nil
			}
		}
	}

	var token model.Token
	err := r.getDB().Where("refresh_token = ?", refreshToken).First(&token).Error
	if err != nil {
		return nil, err
	}

	if rc != nil {
		cacheKey := fmt.Sprintf("token:refresh:%s", refreshToken)
		data, err := json.Marshal(token)
		if err == nil {
			expiration := time.Until(token.RefreshExpiresAt) / 2
			if expiration > 0 {
				rc.Set(context.Background(), cacheKey, data, expiration)
			}
		}
	}

	return &token, nil
}

func (r *tokenDaoImpl) Update(token *model.Token) (*model.Token, error) {
	err := r.getDB().Save(token).Error
	if err != nil {
		return nil, err
	}

	rc := r.getRedis()
	if rc != nil {
		if token.AccessToken != "" {
			cacheKey := fmt.Sprintf("token:access:%s", token.AccessToken)
			data, err := json.Marshal(token)
			if err == nil {
				expiration := time.Until(token.ExpiresAt) / 2
				if expiration > 0 {
					rc.Set(context.Background(), cacheKey, data, expiration)
				}
			}
		}

		if token.RefreshToken != "" {
			cacheKey := fmt.Sprintf("token:refresh:%s", token.RefreshToken)
			data, err := json.Marshal(token)
			if err == nil {
				expiration := time.Until(token.RefreshExpiresAt) / 2
				if expiration > 0 {
					rc.Set(context.Background(), cacheKey, data, expiration)
				}
			}
		}
	}

	return token, nil
}

func (r *tokenDaoImpl) Delete(id uint) error {
	var token model.Token
	if err := r.getDB().First(&token, id).Error; err == nil {
		rc := r.getRedis()
		if rc != nil {
			if token.AccessToken != "" {
				cacheKey := fmt.Sprintf("token:access:%s", token.AccessToken)
				rc.Del(context.Background(), cacheKey)
			}
			if token.RefreshToken != "" {
				cacheKey := fmt.Sprintf("token:refresh:%s", token.RefreshToken)
				rc.Del(context.Background(), cacheKey)
			}
		}
	}

	return r.getDB().Delete(&model.Token{}, id).Error
}

func (r *tokenDaoImpl) FindByUserID(userID uint) ([]*model.Token, error) {
	var tokens []*model.Token
	err := r.getDB().Where("user_id = ? AND revoked = ?", userID, false).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *tokenDaoImpl) RevokeByUserID(userID uint) error {
	return r.getDB().Model(&model.Token{}).Where("user_id = ? AND revoked = ?", userID, false).Update("revoked", true).Error
}

func (r *tokenDaoImpl) CreateAuthorizationCode(code *model.AuthorizationCode) (*model.AuthorizationCode, error) {
	err := r.getDB().Create(code).Error
	if err != nil {
		return nil, err
	}
	return code, nil
}

func (r *tokenDaoImpl) FindByCode(code string) (*model.AuthorizationCode, error) {
	var authCode model.AuthorizationCode
	err := r.getDB().Where("code = ?", code).First(&authCode).Error
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

func (r *tokenDaoImpl) MarkAsUsed(id uint) error {
	return r.getDB().Model(&model.AuthorizationCode{}).Where("id = ?", id).Update("used", true).Error
}

// DeleteExpiredCodes 删除已过期的授权码。
// 用参数传入当前时间而不是 SQL 的 NOW()：NOW() 是 MySQL 专有函数，
// SQLite 下会直接报 "no such function: NOW"（清理任务每次执行都失败，
// 过期授权码永远不被删除，表无限增长）。
func (r *tokenDaoImpl) DeleteExpiredCodes() error {
	return r.getDB().Where("expires_at < ?", time.Now()).Delete(&model.AuthorizationCode{}).Error
}

// DeleteExpiredTokens 物理删除已无用的令牌记录。
// 删除条件：refresh 令牌已过期（此时无论如何都不能再刷新），或已撤销。
// 注意不能用 expires_at（access 过期）判断：access 过期但 refresh 未过期时，
// 用户仍可凭 refresh 换取新令牌，此时删记录会导致 refresh 链断裂。
func (r *tokenDaoImpl) DeleteExpiredTokens(now time.Time) (int64, error) {
	db := r.getDB().Where("refresh_expires_at < ? OR revoked = ?", now, true)
	res := db.Delete(&model.Token{})
	return res.RowsAffected, res.Error
}

func (r *tokenDaoImpl) GetRedisClient() redis.UniversalClient {
	return r.getRedis()
}
