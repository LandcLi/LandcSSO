package repository

import (
	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"
)

// AuditRepository 审计日志仓库
type AuditRepository struct {
	dbmanager *dbmanager.DBManager
}

// NewAuditRepository 创建审计日志仓库实例
func NewAuditRepository(dbmanager *dbmanager.DBManager) *AuditRepository {
	return &AuditRepository{
		dbmanager: dbmanager,
	}
}

// Create 创建审计事件
func (r *AuditRepository) Create(event *model.AuditEvent) (*model.AuditEvent, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	err = db.Create(event).Error
	if err != nil {
		return nil, err
	}
	return event, nil
}

// FindByID 根据ID查找审计事件
func (r *AuditRepository) FindByID(id uint) (*model.AuditEvent, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var event model.AuditEvent
	err = db.First(&event, id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// FindByUserID 根据用户ID查找审计事件
func (r *AuditRepository) FindByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, 0, err
		}
	}
	var events []*model.AuditEvent
	var total int64

	// 计算总数
	err = db.Model(&model.AuditEvent{}).Where("user_id = ?", userID).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = db.Where("user_id = ?", userID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// FindByEventType 根据事件类型查找审计事件
func (r *AuditRepository) FindByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, 0, err
		}
	}
	var events []*model.AuditEvent
	var total int64

	// 计算总数
	err = db.Model(&model.AuditEvent{}).Where("event_type = ?", eventType).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = db.Where("event_type = ?", eventType).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// FindAll 查找所有审计事件
func (r *AuditRepository) FindAll(page, pageSize int) ([]*model.AuditEvent, int64, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, 0, err
		}
	}
	var events []*model.AuditEvent
	var total int64

	// 计算总数
	err = db.Model(&model.AuditEvent{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = db.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// Delete 删除审计事件
func (r *AuditRepository) Delete(id uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Delete(&model.AuditEvent{}, id).Error
}

// DeleteByUserID 删除用户的所有审计事件
func (r *AuditRepository) DeleteByUserID(userID uint) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Where("user_id = ?", userID).Delete(&model.AuditEvent{}).Error
}

// DeleteBefore 删除指定时间之前的审计事件
func (r *AuditRepository) DeleteBefore(before interface{}) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	return db.Where("created_at < ?", before).Delete(&model.AuditEvent{}).Error
}
