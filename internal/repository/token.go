package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"

	"github.com/go-redis/redis/v8"
)

// TokenRepository 令牌仓库
type TokenRepository struct {
	dbmanager   *dbmanager.DBManager
	redisClient redis.UniversalClient
}

// NewTokenRepository 创建令牌仓库实例
func NewTokenRepository(dbmanager *dbmanager.DBManager, redisClient redis.UniversalClient) *TokenRepository {
	return &TokenRepository{
		dbmanager:   dbmanager,
		redisClient: redisClient,
	}
}

// Create 创建令牌
func (r *TokenRepository) Create(token *model.Token) (*model.Token, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Create(token).Error
	if err != nil {
		return nil, err
	}
	return token, nil
}

// FindByID 根据ID查找令牌
func (r *TokenRepository) FindByID(id uint) (*model.Token, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var token model.Token
	err = db.First(&token, id).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// FindByAccessToken 根据访问令牌查找令牌
func (r *TokenRepository) FindByAccessToken(accessToken string) (*model.Token, error) {
	// 先从缓存中查找
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

	// 缓存未命中，从数据库中查找
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var token model.Token
	err = db.Where("access_token = ?", accessToken).First(&token).Error
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("token:access:%s", accessToken)
		data, err := json.Marshal(token)
		if err == nil {
			// 设置缓存，过期时间为令牌剩余有效期的一半
			expiration := time.Until(token.ExpiresAt) / 2
			if expiration > 0 {
				r.redisClient.Set(context.Background(), cacheKey, data, expiration)
			}
		}
	}

	return &token, nil
}

// FindByRefreshToken 根据刷新令牌查找令牌
func (r *TokenRepository) FindByRefreshToken(refreshToken string) (*model.Token, error) {
	// 先从缓存中查找
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

	// 缓存未命中，从数据库中查找
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var token model.Token
	err = db.Where("refresh_token = ?", refreshToken).First(&token).Error
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("token:refresh:%s", refreshToken)
		data, err := json.Marshal(token)
		if err == nil {
			// 设置缓存，过期时间为令牌剩余有效期的一半
			expiration := time.Until(token.RefreshExpiresAt) / 2
			if expiration > 0 {
				r.redisClient.Set(context.Background(), cacheKey, data, expiration)
			}
		}
	}

	return &token, nil
}

// Update 更新令牌
func (r *TokenRepository) Update(token *model.Token) (*model.Token, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Save(token).Error
	if err != nil {
		return nil, err
	}

	// 更新缓存
	if r.redisClient != nil {
		// 更新访问令牌缓存
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

		// 更新刷新令牌缓存
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

// Delete 删除令牌
func (r *TokenRepository) Delete(id uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	// 先获取令牌信息，以便删除缓存
	var token model.Token
	if err := db.First(&token, id).Error; err == nil {
		// 删除缓存
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

	return db.Delete(&model.Token{}, id).Error
}

// FindByUserID 根据用户ID查找令牌
func (r *TokenRepository) FindByUserID(userID uint) ([]*model.Token, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var tokens []*model.Token
	err = db.Where("user_id = ? AND revoked = ?", userID, false).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// RevokeByUserID 撤销用户的所有令牌
func (r *TokenRepository) RevokeByUserID(userID uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Model(&model.Token{}).Where("user_id = ? AND revoked = ?", userID, false).Update("revoked", true).Error
}

// CreateAuthorizationCode 创建授权码
func (r *TokenRepository) CreateAuthorizationCode(code *model.AuthorizationCode) (*model.AuthorizationCode, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Create(code).Error
	if err != nil {
		return nil, err
	}
	return code, nil
}

// FindByCode 根据授权码查找
func (r *TokenRepository) FindByCode(code string) (*model.AuthorizationCode, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var authCode model.AuthorizationCode
	err = db.Where("code = ?", code).First(&authCode).Error
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

// MarkAsUsed 标记授权码为已使用
func (r *TokenRepository) MarkAsUsed(id uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Model(&model.AuthorizationCode{}).Where("id = ?", id).Update("used", true).Error
}

// DeleteExpiredCodes 删除过期的授权码
func (r *TokenRepository) DeleteExpiredCodes() error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Where("expires_at < NOW()").Delete(&model.AuthorizationCode{}).Error
}

// GetRedisClient 获取Redis客户端
func (r *TokenRepository) GetRedisClient() redis.UniversalClient {
	return r.redisClient
}
