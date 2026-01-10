package repository

import (
	"github.com/LandcLi/LandcSSO/internal/model"

	"gorm.io/gorm"
)

// AuditRepository 审计日志仓库
type AuditRepository struct {
	db *gorm.DB
}

// NewAuditRepository 创建审计日志仓库实例
func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{
		db: db,
	}
}

// Create 创建审计事件
func (r *AuditRepository) Create(event *model.AuditEvent) (*model.AuditEvent, error) {
	err := r.db.Create(event).Error
	if err != nil {
		return nil, err
	}
	return event, nil
}

// FindByID 根据ID查找审计事件
func (r *AuditRepository) FindByID(id uint) (*model.AuditEvent, error) {
	var event model.AuditEvent
	err := r.db.First(&event, id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// FindByUserID 根据用户ID查找审计事件
func (r *AuditRepository) FindByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	// 计算总数
	err := r.db.Model(&model.AuditEvent{}).Where("user_id = ?", userID).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = r.db.Where("user_id = ?", userID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// FindByEventType 根据事件类型查找审计事件
func (r *AuditRepository) FindByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	// 计算总数
	err := r.db.Model(&model.AuditEvent{}).Where("event_type = ?", eventType).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = r.db.Where("event_type = ?", eventType).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// FindAll 查找所有审计事件
func (r *AuditRepository) FindAll(page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	// 计算总数
	err := r.db.Model(&model.AuditEvent{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	err = r.db.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// Delete 删除审计事件
func (r *AuditRepository) Delete(id uint) error {
	return r.db.Delete(&model.AuditEvent{}, id).Error
}

// DeleteByUserID 删除用户的所有审计事件
func (r *AuditRepository) DeleteByUserID(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.AuditEvent{}).Error
}

// DeleteBefore 删除指定时间之前的审计事件
func (r *AuditRepository) DeleteBefore(before interface{}) error {
	return r.db.Where("created_at < ?", before).Delete(&model.AuditEvent{}).Error
}
