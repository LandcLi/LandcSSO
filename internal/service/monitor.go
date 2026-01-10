package service

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/LandcLi/LandcSSO/internal/model"
	"github.com/LandcLi/LandcSSO/internal/repository"
	"github.com/LandcLi/LandcSSO/pkg/config"
	"github.com/LandcLi/LandcSSO/pkg/logger"
)

// MonitorService 监控服务
type MonitorService struct {
	monitorRepo       *repository.MonitorRepository
	auditService      *AuditService
	config            *config.Config
	authSuccessCount  int64
	authFailureCount  int64
	tokenIssuedCount  int64
	tokenRevokedCount int64
}

// NewMonitorService 创建监控服务实例
func NewMonitorService(monitorRepo *repository.MonitorRepository, auditService *AuditService, config *config.Config) *MonitorService {
	return &MonitorService{
		monitorRepo:       monitorRepo,
		auditService:      auditService,
		config:            config,
		authSuccessCount:  0,
		authFailureCount:  0,
		tokenIssuedCount:  0,
		tokenRevokedCount: 0,
	}
}

// CollectSystemMetrics 收集系统指标
func (s *MonitorService) CollectSystemMetrics(ctx context.Context) error {
	// 收集CPU和内存使用情况
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// 内存使用量（MB）
	memoryUsage := float64(memStats.Alloc) / 1024 / 1024

	// CPU使用量（简化版，实际项目中可以使用更复杂的方法）
	cpuUsage := float64(runtime.NumGoroutine()) / 100.0

	// 记录内存使用指标
	s.recordMetric(ctx, "system", "memory_usage", memoryUsage, map[string]string{
		"unit": "MB",
	})

	// 记录CPU使用指标
	s.recordMetric(ctx, "system", "cpu_usage", cpuUsage, map[string]string{
		"unit":       "%",
		"goroutines": fmt.Sprintf("%d", runtime.NumGoroutine()),
	})

	// 记录goroutine数量
	s.recordMetric(ctx, "system", "goroutine_count", float64(runtime.NumGoroutine()), map[string]string{})

	return nil
}

// RecordAuthEvent 记录认证事件
func (s *MonitorService) RecordAuthEvent(ctx context.Context, success bool, userID uint, ip string, deviceFingerprint string) {
	if success {
		s.authSuccessCount++
	} else {
		s.authFailureCount++
	}

	// 每10次认证事件计算一次成功率
	if (s.authSuccessCount+s.authFailureCount)%10 == 0 {
		s.calculateAuthSuccessRate(ctx)
	}

	// 记录认证事件到审计日志
	if s.auditService != nil {
		eventType := "auth_success"
		status := "success"
		if !success {
			eventType = "auth_failure"
			status = "failure"
		}
		s.auditService.LogEvent(eventType, userID, "", ip, "", fmt.Sprintf("用户 %d 认证%s", userID, map[bool]string{true: "成功", false: "失败"}[success]), status)
	}
}

// RecordTokenEvent 记录令牌事件
func (s *MonitorService) RecordTokenEvent(ctx context.Context, eventType string, userID uint, clientID string, ip string) {
	switch eventType {
	case "issued":
		s.tokenIssuedCount++
	case "revoked":
		s.tokenRevokedCount++
	}

	// 每10次令牌事件记录一次指标
	if (s.tokenIssuedCount+s.tokenRevokedCount)%10 == 0 {
		s.recordTokenMetrics(ctx)
	}

	// 记录令牌事件到审计日志
	if s.auditService != nil {
		s.auditService.LogEvent(fmt.Sprintf("token_%s", eventType), userID, "", ip, "", fmt.Sprintf("用户 %d 令牌%s", userID, map[string]string{"issued": "颁发", "revoked": "撤销"}[eventType]), "success")
	}
}

// DetectAnomaly 检测异常
func (s *MonitorService) DetectAnomaly(ctx context.Context, eventType string, userID uint, ip string, deviceFingerprint string, details map[string]interface{}) (bool, string) {
	switch eventType {
	case "login":
		// 登录异常检测
		return s.detectLoginAnomaly(ctx, userID, ip, deviceFingerprint, details)
	case "token":
		// 令牌异常检测
		return s.detectTokenAnomaly(ctx, userID, ip, details)
	case "behavior":
		// 行为异常检测
		return s.detectBehaviorAnomaly(ctx, userID, details)
	default:
		return false, "未知事件类型"
	}
}

// GetSystemStatus 获取系统状态
func (s *MonitorService) GetSystemStatus(ctx context.Context) (map[string]interface{}, error) {
	// 收集最新的系统指标
	s.CollectSystemMetrics(ctx)

	// 获取最近的系统指标
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute)

	metrics, err := s.monitorRepo.GetMetricsByType("system", startTime, endTime, 10)
	if err != nil {
		return nil, err
	}

	// 构建系统状态响应
	metricsSlice := make([]map[string]interface{}, 0)
	for _, metric := range metrics {
		metricsSlice = append(metricsSlice, map[string]interface{}{
			"name":  metric.MetricName,
			"value": metric.MetricValue,
			"time":  metric.Timestamp,
		})
	}

	status := map[string]interface{}{
		"timestamp": endTime,
		"metrics":   metricsSlice,
	}

	return status, nil
}

// GetAuthMetrics 获取认证指标
func (s *MonitorService) GetAuthMetrics(ctx context.Context, startTime, endTime time.Time) ([]*model.MonitorMetric, error) {
	return s.monitorRepo.GetMetricsByType("auth", startTime, endTime, 100)
}

// GetTokenMetrics 获取令牌指标
func (s *MonitorService) GetTokenMetrics(ctx context.Context, startTime, endTime time.Time) ([]*model.MonitorMetric, error) {
	return s.monitorRepo.GetMetricsByType("token", startTime, endTime, 100)
}

// GetAnomalyEvents 获取异常事件
func (s *MonitorService) GetAnomalyEvents(ctx context.Context, startTime, endTime time.Time, severity string) ([]*model.AnomalyEvent, error) {
	return s.monitorRepo.GetAnomalyEvents(startTime, endTime, severity, 100)
}

// calculateAuthSuccessRate 计算认证成功率
func (s *MonitorService) calculateAuthSuccessRate(ctx context.Context) {
	total := s.authSuccessCount + s.authFailureCount
	if total == 0 {
		return
	}

	successRate := float64(s.authSuccessCount) / float64(total) * 100

	s.recordMetric(ctx, "auth", "success_rate", successRate, map[string]string{
		"unit":    "%",
		"total":   fmt.Sprintf("%d", total),
		"success": fmt.Sprintf("%d", s.authSuccessCount),
		"failure": fmt.Sprintf("%d", s.authFailureCount),
	})
}

// recordTokenMetrics 记录令牌指标
func (s *MonitorService) recordTokenMetrics(ctx context.Context) {
	// 记录令牌颁发频率
	s.recordMetric(ctx, "token", "issued_count", float64(s.tokenIssuedCount), map[string]string{})

	// 记录令牌撤销频率
	s.recordMetric(ctx, "token", "revoked_count", float64(s.tokenRevokedCount), map[string]string{})
}

// recordMetric 记录指标
func (s *MonitorService) recordMetric(ctx context.Context, metricType, metricName string, value float64, labels map[string]string) {
	labelsJSON, _ := json.Marshal(labels)

	metric := &model.MonitorMetric{
		MetricType:  metricType,
		MetricName:  metricName,
		MetricValue: value,
		Labels:      string(labelsJSON),
		Timestamp:   time.Now(),
	}

	_, err := s.monitorRepo.CreateMetric(metric)
	if err != nil {
		logger.Errorf(ctx, "记录监控指标失败: %v", err)
	}
}

// detectLoginAnomaly 检测登录异常
func (s *MonitorService) detectLoginAnomaly(ctx context.Context, userID uint, ip string, deviceFingerprint string, details map[string]interface{}) (bool, string) {
	// 简单的登录异常检测逻辑
	// 1. 短时间内多次登录失败
	// 2. 异地登录（IP地址变化）
	// 3. 设备指纹变化

	// 这里实现一个简化版本，实际项目中可以使用更复杂的算法
	loginFailures, ok := details["login_failures"].(int)
	if ok && loginFailures > 5 {
		description := fmt.Sprintf("用户 %d 在短时间内登录失败 %d 次", userID, loginFailures)
		s.createAnomalyEvent(ctx, "login_anomaly", "high", description, userID, ip, deviceFingerprint)
		return true, description
	}

	is异地Login, ok := details["is_abnormal_login"].(bool)
	if ok && is异地Login {
		description := fmt.Sprintf("用户 %d 疑似异地登录，IP: %s", userID, ip)
		s.createAnomalyEvent(ctx, "login_anomaly", "medium", description, userID, ip, deviceFingerprint)
		return true, description
	}

	return false, ""
}

// detectTokenAnomaly 检测令牌异常
func (s *MonitorService) detectTokenAnomaly(ctx context.Context, userID uint, ip string, details map[string]interface{}) (bool, string) {
	// 简单的令牌异常检测逻辑
	// 1. 短时间内多次令牌刷新
	// 2. 令牌使用地点异常

	tokenRefreshes, ok := details["token_refreshes"].(int)
	if ok && tokenRefreshes > 10 {
		description := fmt.Sprintf("用户 %d 在短时间内令牌刷新 %d 次", userID, tokenRefreshes)
		s.createAnomalyEvent(ctx, "token_anomaly", "medium", description, userID, ip, "")
		return true, description
	}

	return false, ""
}

// detectBehaviorAnomaly 检测行为异常
func (s *MonitorService) detectBehaviorAnomaly(ctx context.Context, userID uint, details map[string]interface{}) (bool, string) {
	// 简单的行为异常检测逻辑
	// 1. 操作频率异常
	// 2. 操作模式变化

	operationCount, ok := details["operation_count"].(int)
	if ok && operationCount > 50 {
		description := fmt.Sprintf("用户 %d 在短时间内操作 %d 次，可能存在异常", userID, operationCount)
		s.createAnomalyEvent(ctx, "behavior_anomaly", "low", description, userID, "", "")
		return true, description
	}

	return false, ""
}

// createAnomalyEvent 创建异常事件
func (s *MonitorService) createAnomalyEvent(ctx context.Context, eventType, severity, description string, userID uint, ip, deviceFingerprint string) {
	event := &model.AnomalyEvent{
		EventType:         eventType,
		Severity:          severity,
		Description:       description,
		UserID:            userID,
		IP:                ip,
		DeviceFingerprint: deviceFingerprint,
		Status:            "pending",
		Timestamp:         time.Now(),
	}

	_, err := s.monitorRepo.CreateAnomalyEvent(event)
	if err != nil {
		logger.Errorf(ctx, "创建异常事件失败: %v", err)
	}

	// 记录到审计日志
	if s.auditService != nil {
		s.auditService.LogEvent("security_anomaly", userID, "", ip, "", description, "warning")
	}
}
