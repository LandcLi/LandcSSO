package dao

import (
	"github.com/LandcLi/LandcSSO/model"
)

type auditDao interface {
	Create(event *model.AuditEvent) (*model.AuditEvent, error)
	FindByID(id uint) (*model.AuditEvent, error)
	FindByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error)
	FindByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error)
	FindAll(page, pageSize int) ([]*model.AuditEvent, int64, error)
	Delete(id uint) error
	DeleteByUserID(userID uint) error
	DeleteBefore(before interface{}) error
}

var auditDaoImpl auditDao

func RegisterAuditDaoImpl(impl auditDao) {
	auditDaoImpl = impl
}

func GetAuditDao() auditDao {
	return auditDaoImpl
}
