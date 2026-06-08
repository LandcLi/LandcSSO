package audit

import (
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"gorm.io/gorm"
)

type auditDaoImpl struct{}

func NewAuditDaoImpl() *auditDaoImpl {
	return &auditDaoImpl{}
}

func (r *auditDaoImpl) getDB() *gorm.DB {
	return config.GetDB()
}

func init() {
	if dao.GetAuditDao() == nil {
		dao.RegisterAuditDaoImpl(NewAuditDaoImpl())
	}
}

func (r *auditDaoImpl) Create(event *model.AuditEvent) (*model.AuditEvent, error) {
	err := r.getDB().Create(event).Error
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (r *auditDaoImpl) FindByID(id uint) (*model.AuditEvent, error) {
	var event model.AuditEvent
	err := r.getDB().First(&event, id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func (r *auditDaoImpl) FindByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	err := r.getDB().Model(&model.AuditEvent{}).Where("user_id = ?", userID).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.getDB().Where("user_id = ?", userID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

func (r *auditDaoImpl) FindByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	err := r.getDB().Model(&model.AuditEvent{}).Where("event_type = ?", eventType).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.getDB().Where("event_type = ?", eventType).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

func (r *auditDaoImpl) FindAll(page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	err := r.getDB().Model(&model.AuditEvent{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.getDB().Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

func (r *auditDaoImpl) Delete(id uint) error {
	return r.getDB().Delete(&model.AuditEvent{}, id).Error
}

func (r *auditDaoImpl) DeleteByUserID(userID uint) error {
	return r.getDB().Where("user_id = ?", userID).Delete(&model.AuditEvent{}).Error
}

func (r *auditDaoImpl) DeleteBefore(before interface{}) error {
	return r.getDB().Where("created_at < ?", before).Delete(&model.AuditEvent{}).Error
}
