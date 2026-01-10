package repository

import (
	"github.com/LandcLi/LandcSSO/internal/model"
	"gorm.io/gorm"
)

// LoginHistoryRepository 登录历史记录仓库
type LoginHistoryRepository struct {
	db *gorm.DB
}

// NewLoginHistoryRepository 创建登录历史记录仓库实例
func NewLoginHistoryRepository(db *gorm.DB) *LoginHistoryRepository {
	return &LoginHistoryRepository{
		db: db,
	}
}

// Create 创建登录历史记录
func (r *LoginHistoryRepository) Create(history *model.LoginHistory) (*model.LoginHistory, error) {
	result := r.db.Create(history)
	return history, result.Error
}

// FindByUserID 查找用户的登录历史记录
func (r *LoginHistoryRepository) FindByUserID(userID uint, limit int) ([]*model.LoginHistory, error) {
	var histories []*model.LoginHistory
	result := r.db.Where("user_id = ?", userID).Order("login_time DESC").Limit(limit).Find(&histories)
	return histories, result.Error
}

// FindLatestByUserID 查找用户最近的登录记录
func (r *LoginHistoryRepository) FindLatestByUserID(userID uint) (*model.LoginHistory, error) {
	var history model.LoginHistory
	result := r.db.Where("user_id = ?", userID).Order("login_time DESC").First(&history)
	if result.Error != nil {
		return nil, result.Error
	}
	return &history, nil
}

// FindByIPAndUserID 根据IP和用户ID查找登录记录
func (r *LoginHistoryRepository) FindByIPAndUserID(userID uint, ip string) (*model.LoginHistory, error) {
	var history model.LoginHistory
	result := r.db.Where("user_id = ? AND ip = ?", userID, ip).Order("login_time DESC").First(&history)
	if result.Error != nil {
		return nil, result.Error
	}
	return &history, nil
}
