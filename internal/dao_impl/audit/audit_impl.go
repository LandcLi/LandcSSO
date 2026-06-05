package audit

import (
	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"gorm.io/gorm"
)

func init() {
	if dao.GetAuditDao() == nil {
		dao.RegisterAuditDaoImpl(NewAuditDaoImpl())
	}
}

type auditDaoImpl struct {
	db *gorm.DB
}

func NewAuditDaoImpl() *auditDaoImpl {
	return &auditDaoImpl{
		db: config.GetDB(),
	}
}

func (r *auditDaoImpl) Create(event *model.AuditEvent) (*model.AuditEvent, error) {
	err := r.db.Create(event).Error
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (r *auditDaoImpl) FindByID(id uint) (*model.AuditEvent, error) {
	var event model.AuditEvent
	err := r.db.First(&event, id).Error
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func (r *auditDaoImpl) FindByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	err := r.db.Model(&model.AuditEvent{}).Where("user_id = ?", userID).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.db.Where("user_id = ?", userID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

func (r *auditDaoImpl) FindByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	err := r.db.Model(&model.AuditEvent{}).Where("event_type = ?", eventType).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.db.Where("event_type = ?", eventType).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

func (r *auditDaoImpl) FindAll(page, pageSize int) ([]*model.AuditEvent, int64, error) {
	var events []*model.AuditEvent
	var total int64

	err := r.db.Model(&model.AuditEvent{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = r.db.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events).Error
	if err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

func (r *auditDaoImpl) Delete(id uint) error {
	return r.db.Delete(&model.AuditEvent{}, id).Error
}

func (r *auditDaoImpl) DeleteByUserID(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.AuditEvent{}).Error
}

func (r *auditDaoImpl) DeleteBefore(before interface{}) error {
	return r.db.Where("created_at < ?", before).Delete(&model.AuditEvent{}).Error
}
