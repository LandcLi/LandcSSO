package repository

import (
	"github.com/LandcLi/LandcSSO/internal/model"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// TrustedDeviceRepository 信任设备仓库
type TrustedDeviceRepository struct {
	db          *gorm.DB
	redisClient redis.UniversalClient
}

// NewTrustedDeviceRepository 创建信任设备仓库实例
func NewTrustedDeviceRepository(db *gorm.DB, redisClient redis.UniversalClient) *TrustedDeviceRepository {
	return &TrustedDeviceRepository{
		db:          db,
		redisClient: redisClient,
	}
}

// Create 创建信任设备
func (r *TrustedDeviceRepository) Create(device *model.TrustedDevice) (*model.TrustedDevice, error) {
	err := r.db.Create(device).Error
	if err != nil {
		return nil, err
	}
	return device, nil
}

// FindByUserIDAndFingerprint 根据用户ID和设备指纹查找信任设备
func (r *TrustedDeviceRepository) FindByUserIDAndFingerprint(userID uint, deviceFingerprint string) (*model.TrustedDevice, error) {
	var device model.TrustedDevice
	err := r.db.Where("user_id = ? AND device_fingerprint = ?", userID, deviceFingerprint).First(&device).Error
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// FindByUserID 根据用户ID查找所有信任设备
func (r *TrustedDeviceRepository) FindByUserID(userID uint) ([]*model.TrustedDevice, error) {
	var devices []*model.TrustedDevice
	err := r.db.Where("user_id = ?", userID).Find(&devices).Error
	if err != nil {
		return nil, err
	}
	return devices, nil
}

// Update 更新信任设备
func (r *TrustedDeviceRepository) Update(device *model.TrustedDevice) (*model.TrustedDevice, error) {
	err := r.db.Save(device).Error
	if err != nil {
		return nil, err
	}
	return device, nil
}

// Delete 删除信任设备
func (r *TrustedDeviceRepository) Delete(id uint) error {
	return r.db.Delete(&model.TrustedDevice{}, id).Error
}

// DeleteByUserIDAndFingerprint 根据用户ID和设备指纹删除信任设备
func (r *TrustedDeviceRepository) DeleteByUserIDAndFingerprint(userID uint, deviceFingerprint string) error {
	return r.db.Where("user_id = ? AND device_fingerprint = ?", userID, deviceFingerprint).Delete(&model.TrustedDevice{}).Error
}
