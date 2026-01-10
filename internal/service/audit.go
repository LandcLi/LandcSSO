package service

import (
	"context"
	"time"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/pkg/logger"
)

// AuditService 审计日志服务
type AuditService struct {
	auditRepo *repository.AuditRepository
}

// NewAuditService 创建审计日志服务实例
func NewAuditService(auditRepo *repository.AuditRepository) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
	}
}

// LogEvent 记录审计事件
func (s *AuditService) LogEvent(eventType string, userID uint, username string, ip string, userAgent string, details string, status string) error {
	ctx := context.Background()
	// 创建审计事件
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

	// 保存审计事件
	_, err := s.auditRepo.Create(event)
	if err != nil {
		logger.Errorf(ctx, "记录审计事件失败: %v", err)
		return err
	}

	// 同时输出到日志
	logger.Info(ctx, "审计事件")

	return nil
}

// LogLogin 记录登录事件
func (s *AuditService) LogLogin(userID uint, username string, ip string, userAgent string, success bool) error {
	status := "success"
	if !success {
		status = "failure"
	}

	return s.LogEvent("login", userID, username, ip, userAgent, "用户登录", status)
}

// LogLogout 记录登出事件
func (s *AuditService) LogLogout(userID uint, username string, ip string, userAgent string) error {
	return s.LogEvent("logout", userID, username, ip, userAgent, "用户登出", "success")
}

// LogTokenIssuance 记录令牌颁发事件
func (s *AuditService) LogTokenIssuance(userID uint, username string, ip string, userAgent string, clientID string) error {
	return s.LogEvent("token_issuance", userID, username, ip, userAgent, "颁发访问令牌", "success")
}

// LogTokenRevocation 记录令牌撤销事件
func (s *AuditService) LogTokenRevocation(userID uint, username string, ip string, userAgent string) error {
	return s.LogEvent("token_revocation", userID, username, ip, userAgent, "撤销访问令牌", "success")
}

// LogPasswordChange 记录密码修改事件
func (s *AuditService) LogPasswordChange(userID uint, username string, ip string, userAgent string, success bool) error {
	status := "success"
	if !success {
		status = "failure"
	}

	return s.LogEvent("password_change", userID, username, ip, userAgent, "修改密码", status)
}

// LogUserRegistration 记录用户注册事件
func (s *AuditService) LogUserRegistration(userID uint, username string, ip string, userAgent string, success bool) error {
	status := "success"
	if !success {
		status = "failure"
	}

	return s.LogEvent("user_registration", userID, username, ip, userAgent, "用户注册", status)
}

// GetEventsByUserID 获取用户的审计事件
func (s *AuditService) GetEventsByUserID(userID uint, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	return s.auditRepo.FindByUserID(userID, page, pageSize)
}

// GetEventsByEventType 获取指定类型的审计事件
func (s *AuditService) GetEventsByEventType(eventType string, page, pageSize int) ([]*model.AuditEvent, int64, error) {
	return s.auditRepo.FindByEventType(eventType, page, pageSize)
}

// GetAllEvents 获取所有审计事件
func (s *AuditService) GetAllEvents(page, pageSize int) ([]*model.AuditEvent, int64, error) {
	return s.auditRepo.FindAll(page, pageSize)
}

// GetEventByID 获取单个审计事件详情
func (s *AuditService) GetEventByID(id uint) (*model.AuditEvent, error) {
	return s.auditRepo.FindByID(id)
}
