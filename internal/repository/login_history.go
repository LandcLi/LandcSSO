package repository

import (
	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"
)

// LoginHistoryRepository 登录历史记录仓库
type LoginHistoryRepository struct {
	dbmanager *dbmanager.DBManager
}

// NewLoginHistoryRepository 创建登录历史记录仓库实例
func NewLoginHistoryRepository(dbmanager *dbmanager.DBManager) *LoginHistoryRepository {
	return &LoginHistoryRepository{
		dbmanager: dbmanager,
	}
}

// Create 创建登录历史记录
func (r *LoginHistoryRepository) Create(history *model.LoginHistory) (*model.LoginHistory, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	result := db.Create(history)
	return history, result.Error
}

// FindByUserID 查找用户的登录历史记录
func (r *LoginHistoryRepository) FindByUserID(userID uint, limit int) ([]*model.LoginHistory, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var histories []*model.LoginHistory
	result := db.Where("user_id = ?", userID).Order("login_time DESC").Limit(limit).Find(&histories)
	return histories, result.Error
}

// FindLatestByUserID 查找用户最近的登录记录
func (r *LoginHistoryRepository) FindLatestByUserID(userID uint) (*model.LoginHistory, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var history model.LoginHistory
	result := db.Where("user_id = ?", userID).Order("login_time DESC").First(&history)
	if result.Error != nil {
		return nil, result.Error
	}
	return &history, nil
}

// FindByIPAndUserID 根据IP和用户ID查找登录记录
func (r *LoginHistoryRepository) FindByIPAndUserID(userID uint, ip string) (*model.LoginHistory, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var history model.LoginHistory
	result := db.Where("user_id = ? AND ip = ?", userID, ip).Order("login_time DESC").First(&history)
	if result.Error != nil {
		return nil, result.Error
	}
	return &history, nil
}
