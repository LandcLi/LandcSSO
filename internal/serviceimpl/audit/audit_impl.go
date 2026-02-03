package audit

import (
	"context"
	"time"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/logger"
)

type auditServiceImpl struct {
}

func NewAuditServiceImpl() *auditServiceImpl {
	return &auditServiceImpl{}
}

func init() {
	if service.GetAuditService() == nil {
		service.RegisterAuditServiceImpl(NewAuditServiceImpl())
	}
}

func (s *auditServiceImpl) LogEvent(eventType string, userID uint, username string, ip string, userAgent string, details string, status string) error {
	ctx := context.Background()
	event := &model.AuditEvent{
		EventType: eventType,
		UserID:    userID,
		Username:  username,
		IP:        ip,
		UserAgent: userAgent,
		Details:   details,
		Status:    status,
		CreatedAt: time.Now(),
	}

	_, err := dao.GetAuditDao().Create(event)
	if err != nil {
		logger.Errorf(ctx, "记录审计事件失败: %v", err)
		return err
	}

	logger.Info(ctx, "审计事件")

	return nil
}

func (s *auditServiceImpl) LogLogin(userID uint, username string, ip string, userAgent string, success bool) error {
	status := "success"
	if !success {
		status = "failure"
	}

	return s.LogEvent("login", userID, username, ip, userAgent, "用户登录", status)
}

func (s *auditServiceImpl) LogLogout(userID uint, username string, ip string, userAgent string) error {
	return s.LogEvent("logout", userID, username, ip, userAgent, "用户登出", "success")
}

func (s *auditServiceImpl) LogTokenIssuance(userID uint, username string, ip string, userAgent string, clientID string) error {
	return s.LogEvent("token_issuance", userID, username, ip, userAgent, "颁发访问令牌", "success")
}

func (s *auditServiceImpl) LogTokenRevocation(userID uint, username string, ip string, userAgent string) error {
	return s.LogEvent("token_revocation", userID, username, ip, userAgent, "撤销访问令牌", "success")
}

func (s *auditServiceImpl) LogPasswordChange(userID uint, username string, ip string, userAgent string, success bool) error {
	status := "success"
	if !success {
		status = "failure"
	}

	return s.LogEvent("password_change", userID, username, ip, userAgent, "修改密码", status)
}

func (s *auditServiceImpl) LogUserRegistration(userID uint, username string, ip string, userAgent string, success bool) error {
	status := "success"
	if !success {
		status = "failure"
	}

	return s.LogEvent("user_registration", userID, username, ip, userAgent, "用户注册", status)
}

func (s *auditServiceImpl) GetEventsByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	return dao.GetAuditDao().FindByUserID(userID, page, pageSize)
}

func (s *auditServiceImpl) GetEventsByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	return dao.GetAuditDao().FindByEventType(eventType, page, pageSize)
}

func (s *auditServiceImpl) GetAllEvents(page, pageSize int) ([]*model.AuditEvent, int64, error) {
	return dao.GetAuditDao().FindAll(page, pageSize)
}

func (s *auditServiceImpl) GetEventByID(id uint) (*model.AuditEvent, error) {
	return dao.GetAuditDao().FindByID(id)
}
