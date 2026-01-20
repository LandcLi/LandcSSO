package repository

import (
	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"

	"github.com/go-redis/redis/v8"
)

// ThirdPartyUserRepository 第三方用户仓库
type ThirdPartyUserRepository struct {
	dbmanager   *dbmanager.DBManager
	redisClient redis.UniversalClient
}

// NewThirdPartyUserRepository 创建第三方用户仓库实例
func NewThirdPartyUserRepository(dbmanager *dbmanager.DBManager, redisClient redis.UniversalClient) *ThirdPartyUserRepository {
	return &ThirdPartyUserRepository{
		dbmanager:   dbmanager,
		redisClient: redisClient,
	}
}

// Create 创建第三方用户关联
func (r *ThirdPartyUserRepository) Create(link *model.ThirdPartyUserLink) (*model.ThirdPartyUserLink, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Create(link).Error
	if err != nil {
		return nil, err
	}
	return link, nil
}

// FindByUserIDAndProvider 根据用户ID和提供商查找关联
func (r *ThirdPartyUserRepository) FindByUserIDAndProvider(userID uint, provider string) (*model.ThirdPartyUserLink, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var link model.ThirdPartyUserLink
	err = db.Where("user_id = ? AND provider = ?", userID, provider).First(&link).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// FindByOpenIDAndProvider 根据OpenID和提供商查找关联
func (r *ThirdPartyUserRepository) FindByOpenIDAndProvider(openID string, provider string) (*model.ThirdPartyUserLink, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var link model.ThirdPartyUserLink
	err = db.Where("open_id = ? AND provider = ?", openID, provider).First(&link).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// FindByUnionID 根据UnionID查找关联
func (r *ThirdPartyUserRepository) FindByUnionID(unionID string) (*model.ThirdPartyUserLink, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var link model.ThirdPartyUserLink
	err = db.Where("union_id = ?", unionID).First(&link).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// Update 更新第三方用户关联
func (r *ThirdPartyUserRepository) Update(link *model.ThirdPartyUserLink) (*model.ThirdPartyUserLink, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Save(link).Error
	if err != nil {
		return nil, err
	}
	return link, nil
}

// Delete 删除第三方用户关联
func (r *ThirdPartyUserRepository) Delete(id uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Delete(&model.ThirdPartyUserLink{}, id).Error
}

// FindByUserID 根据用户ID查找所有关联
func (r *ThirdPartyUserRepository) FindByUserID(userID uint) ([]*model.ThirdPartyUserLink, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var links []*model.ThirdPartyUserLink
	err = db.Where("user_id = ?", userID).Find(&links).Error
	if err != nil {
		return nil, err
	}
	return links, nil
}
