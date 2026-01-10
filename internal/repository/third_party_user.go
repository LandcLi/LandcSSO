package repository

import (
	"github.com/LandcLi/LandcSSO/internal/model"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// ThirdPartyUserRepository 第三方用户仓库
type ThirdPartyUserRepository struct {
	db          *gorm.DB
	redisClient redis.UniversalClient
}

// NewThirdPartyUserRepository 创建第三方用户仓库实例
func NewThirdPartyUserRepository(db *gorm.DB, redisClient redis.UniversalClient) *ThirdPartyUserRepository {
	return &ThirdPartyUserRepository{
		db:          db,
		redisClient: redisClient,
	}
}

// Create 创建第三方用户关联
func (r *ThirdPartyUserRepository) Create(link *model.ThirdPartyUserLink) (*model.ThirdPartyUserLink, error) {
	err := r.db.Create(link).Error
	if err != nil {
		return nil, err
	}
	return link, nil
}

// FindByUserIDAndProvider 根据用户ID和提供商查找关联
func (r *ThirdPartyUserRepository) FindByUserIDAndProvider(userID uint, provider string) (*model.ThirdPartyUserLink, error) {
	var link model.ThirdPartyUserLink
	err := r.db.Where("user_id = ? AND provider = ?", userID, provider).First(&link).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// FindByOpenIDAndProvider 根据OpenID和提供商查找关联
func (r *ThirdPartyUserRepository) FindByOpenIDAndProvider(openID string, provider string) (*model.ThirdPartyUserLink, error) {
	var link model.ThirdPartyUserLink
	err := r.db.Where("open_id = ? AND provider = ?", openID, provider).First(&link).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// FindByUnionID 根据UnionID查找关联
func (r *ThirdPartyUserRepository) FindByUnionID(unionID string) (*model.ThirdPartyUserLink, error) {
	var link model.ThirdPartyUserLink
	err := r.db.Where("union_id = ?", unionID).First(&link).Error
	if err != nil {
		return nil, err
	}
	return &link, nil
}

// Update 更新第三方用户关联
func (r *ThirdPartyUserRepository) Update(link *model.ThirdPartyUserLink) (*model.ThirdPartyUserLink, error) {
	err := r.db.Save(link).Error
	if err != nil {
		return nil, err
	}
	return link, nil
}

// Delete 删除第三方用户关联
func (r *ThirdPartyUserRepository) Delete(id uint) error {
	return r.db.Delete(&model.ThirdPartyUserLink{}, id).Error
}

// FindByUserID 根据用户ID查找所有关联
func (r *ThirdPartyUserRepository) FindByUserID(userID uint) ([]*model.ThirdPartyUserLink, error) {
	var links []*model.ThirdPartyUserLink
	err := r.db.Where("user_id = ?", userID).Find(&links).Error
	if err != nil {
		return nil, err
	}
	return links, nil
}
