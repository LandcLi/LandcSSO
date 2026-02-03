package service

import (
	"github.com/LandcLi/LandcSSO/model"
)

type auditService interface {
	LogEvent(eventType string, userID uint, username string, ip string, userAgent string, details string, status string) error
	LogLogin(userID uint, username string, ip string, userAgent string, success bool) error
	LogLogout(userID uint, username string, ip string, userAgent string) error
	LogTokenIssuance(userID uint, username string, ip string, userAgent string, clientID string) error
	LogTokenRevocation(userID uint, username string, ip string, userAgent string) error
	LogPasswordChange(userID uint, username string, ip string, userAgent string, success bool) error
	LogUserRegistration(userID uint, username string, ip string, userAgent string, success bool) error
	GetEventsByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error)
	GetEventsByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error)
	GetAllEvents(page, pageSize int) ([]*model.AuditEvent, int64, error)
	GetEventByID(id uint) (*model.AuditEvent, error)
}

var auditServiceImpl auditService

func RegisterAuditServiceImpl(impl auditService) {
	auditServiceImpl = impl
}

func GetAuditService() auditService {
	return auditServiceImpl
}
