package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LandcLi/LandcSSO/internal/model"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// UserRepository 用户仓库
type UserRepository struct {
	db          *gorm.DB
	redisClient redis.UniversalClient
}

// NewUserRepository 创建用户仓库实例
func NewUserRepository(db *gorm.DB, redisClient redis.UniversalClient) *UserRepository {
	return &UserRepository{
		db:          db,
		redisClient: redisClient,
	}
}

// Create 创建用户
func (r *UserRepository) Create(user *model.User) (*model.User, error) {
	err := r.db.Create(user).Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

// FindByID 根据ID查找用户
func (r *UserRepository) FindByID(id uint) (*model.User, error) {
	// 先从缓存中查找
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:id:%d", id)
		data, err := r.redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var user model.User
			if err := json.Unmarshal(data, &user); err == nil {
				return &user, nil
			}
		}
	}

	// 缓存未命中，从数据库中查找
	var user model.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:id:%d", id)
		data, err := json.Marshal(user)
		if err == nil {
			// 设置缓存，过期时间为1小时
			r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
		}
	}

	return &user, nil
}

// FindByUsername 根据用户名查找用户
func (r *UserRepository) FindByUsername(username string) (*model.User, error) {
	// 先从缓存中查找
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:username:%s", username)
		data, err := r.redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var user model.User
			if err := json.Unmarshal(data, &user); err == nil {
				return &user, nil
			}
		}
	}

	// 缓存未命中，从数据库中查找
	var user model.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:username:%s", username)
		data, err := json.Marshal(user)
		if err == nil {
			// 设置缓存，过期时间为1小时
			r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
		}
	}

	return &user, nil
}

// FindByUsernameFromDB 根据用户名从数据库直接查找用户，跳过缓存
func (r *UserRepository) FindByUsernameFromDB(username string) (*model.User, error) {
	var user model.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByEmail 根据邮箱查找用户
func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	// 先从缓存中查找
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:email:%s", email)
		data, err := r.redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var user model.User
			if err := json.Unmarshal(data, &user); err == nil {
				return &user, nil
			}
		}
	}

	// 缓存未命中，从数据库中查找
	var user model.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:email:%s", email)
		data, err := json.Marshal(user)
		if err == nil {
			// 设置缓存，过期时间为1小时
			r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
		}
	}

	return &user, nil
}

// FindByPhone 根据手机号查找用户
func (r *UserRepository) FindByPhone(phone string) (*model.User, error) {
	// 先从缓存中查找
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:phone:%s", phone)
		data, err := r.redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			var user model.User
			if err := json.Unmarshal(data, &user); err == nil {
				return &user, nil
			}
		}
	}

	// 缓存未命中，从数据库中查找
	var user model.User
	err := r.db.Where("phone = ?", phone).First(&user).Error
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if r.redisClient != nil {
		cacheKey := fmt.Sprintf("user:phone:%s", phone)
		data, err := json.Marshal(user)
		if err == nil {
			// 设置缓存，过期时间为1小时
			r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
		}
	}

	return &user, nil
}

// Update 更新用户
func (r *UserRepository) Update(user *model.User) (*model.User, error) {
	err := r.db.Save(user).Error
	if err != nil {
		return nil, err
	}

	// 更新缓存
	if r.redisClient != nil {
		// 更新ID缓存
		cacheKey := fmt.Sprintf("user:id:%d", user.ID)
		data, err := json.Marshal(user)
		if err == nil {
			r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
		}

		// 更新用户名缓存
		if user.Username != "" {
			cacheKey := fmt.Sprintf("user:username:%s", user.Username)
			data, err := json.Marshal(user)
			if err == nil {
				r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
			}
		}

		// 更新邮箱缓存
		if user.Email != "" {
			cacheKey := fmt.Sprintf("user:email:%s", user.Email)
			data, err := json.Marshal(user)
			if err == nil {
				r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
			}
		}

		// 更新手机号缓存
		if user.Phone != "" {
			cacheKey := fmt.Sprintf("user:phone:%s", user.Phone)
			data, err := json.Marshal(user)
			if err == nil {
				r.redisClient.Set(context.Background(), cacheKey, data, time.Hour)
			}
		}
	}

	return user, nil
}

// Delete 删除用户
func (r *UserRepository) Delete(id uint) error {
	// 先获取用户信息，以便删除缓存
	var user model.User
	if err := r.db.First(&user, id).Error; err == nil {
		// 删除缓存
		if r.redisClient != nil {
			// 删除ID缓存
			cacheKey := fmt.Sprintf("user:id:%d", id)
			r.redisClient.Del(context.Background(), cacheKey)

			// 删除用户名缓存
			if user.Username != "" {
				cacheKey := fmt.Sprintf("user:username:%s", user.Username)
				r.redisClient.Del(context.Background(), cacheKey)
			}

			// 删除邮箱缓存
			if user.Email != "" {
				cacheKey := fmt.Sprintf("user:email:%s", user.Email)
				r.redisClient.Del(context.Background(), cacheKey)
			}

			// 删除手机号缓存
			if user.Phone != "" {
				cacheKey := fmt.Sprintf("user:phone:%s", user.Phone)
				r.redisClient.Del(context.Background(), cacheKey)
			}
		}
	}

	return r.db.Delete(&model.User{}, id).Error
}

// ClearUserCache 清除用户缓存
func (r *UserRepository) ClearUserCache(user *model.User) error {
	// 删除缓存
	if r.redisClient != nil {
		// 删除ID缓存
		cacheKey := fmt.Sprintf("user:id:%d", user.ID)
		r.redisClient.Del(context.Background(), cacheKey)

		// 删除用户名缓存
		if user.Username != "" {
			cacheKey := fmt.Sprintf("user:username:%s", user.Username)
			r.redisClient.Del(context.Background(), cacheKey)
		}

		// 删除邮箱缓存
		if user.Email != "" {
			cacheKey := fmt.Sprintf("user:email:%s", user.Email)
			r.redisClient.Del(context.Background(), cacheKey)
		}

		// 删除手机号缓存
		if user.Phone != "" {
			cacheKey := fmt.Sprintf("user:phone:%s", user.Phone)
			r.redisClient.Del(context.Background(), cacheKey)
		}
	}

	return nil
}

// List 获取用户列表
func (r *UserRepository) List(page, pageSize int) ([]*model.User, int64, error) {
	var users []*model.User
	var total int64

	// 计算总数
	err := r.db.Model(&model.User{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = r.db.Offset(offset).Limit(pageSize).Find(&users).Error
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}
