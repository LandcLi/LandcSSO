package repository

import (
	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"

	"github.com/go-redis/redis/v8"
)

// TrustedDeviceRepository 信任设备仓库
type TrustedDeviceRepository struct {
	dbmanager   *dbmanager.DBManager
	redisClient redis.UniversalClient
}

// NewTrustedDeviceRepository 创建信任设备仓库实例
func NewTrustedDeviceRepository(dbmanager *dbmanager.DBManager, redisClient redis.UniversalClient) *TrustedDeviceRepository {
	return &TrustedDeviceRepository{
		dbmanager:   dbmanager,
		redisClient: redisClient,
	}
}

// Create 创建信任设备
func (r *TrustedDeviceRepository) Create(device *model.TrustedDevice) (*model.TrustedDevice, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Create(device).Error
	if err != nil {
		return nil, err
	}
	return device, nil
}

// FindByUserIDAndFingerprint 根据用户ID和设备指纹查找信任设备
func (r *TrustedDeviceRepository) FindByUserIDAndFingerprint(userID uint, deviceFingerprint string) (*model.TrustedDevice, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var device model.TrustedDevice
	err = db.Where("user_id = ? AND device_fingerprint = ?", userID, deviceFingerprint).First(&device).Error
	if err != nil {
		return nil, err
	}
	return &device, nil
}

// FindByUserID 根据用户ID查找所有信任设备
func (r *TrustedDeviceRepository) FindByUserID(userID uint) ([]*model.TrustedDevice, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var devices []*model.TrustedDevice
	err = db.Where("user_id = ?", userID).Find(&devices).Error
	if err != nil {
		return nil, err
	}
	return devices, nil
}

// Update 更新信任设备
func (r *TrustedDeviceRepository) Update(device *model.TrustedDevice) (*model.TrustedDevice, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Save(device).Error
	if err != nil {
		return nil, err
	}
	return device, nil
}

// Delete 删除信任设备
func (r *TrustedDeviceRepository) Delete(id uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Delete(&model.TrustedDevice{}, id).Error
}

// DeleteByUserIDAndFingerprint 根据用户ID和设备指纹删除信任设备
func (r *TrustedDeviceRepository) DeleteByUserIDAndFingerprint(userID uint, deviceFingerprint string) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Where("user_id = ? AND device_fingerprint = ?", userID, deviceFingerprint).Delete(&model.TrustedDevice{}).Error
}
