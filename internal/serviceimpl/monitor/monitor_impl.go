package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/service"
	"github.com/LandcLi/LandcSSO/utility/config"
	"github.com/LandcLi/LandcSSO/utility/logger"
)

type monitorServiceImpl struct {
	config            *config.Config
	authSuccessCount  int64
	authFailureCount  int64
	tokenIssuedCount  int64
	tokenRevokedCount int64
}

func NewMonitorServiceImpl() *monitorServiceImpl {
	return &monitorServiceImpl{
		authSuccessCount:  0,
		authFailureCount:  0,
		tokenIssuedCount:  0,
		tokenRevokedCount: 0,
	}
}

func init() {
	if service.GetMonitorService() == nil {
		service.RegisterMonitorServiceImpl(NewMonitorServiceImpl())
	}
}

func (s *monitorServiceImpl) CollectSystemMetrics(ctx context.Context) error {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	memoryUsage := float64(memStats.Alloc) / 1024 / 1024

	cpuUsage := float64(runtime.NumGoroutine()) / 100.0

	s.recordMetric(ctx, "system", "memory_usage", memoryUsage, map[string]string{
		"unit": "MB",
	})

	s.recordMetric(ctx, "system", "cpu_usage", cpuUsage, map[string]string{
		"unit":       "%",
		"goroutines": fmt.Sprintf("%d", runtime.NumGoroutine()),
	})

	s.recordMetric(ctx, "system", "goroutine_count", float64(runtime.NumGoroutine()), map[string]string{})

	return nil
}

func (s *monitorServiceImpl) RecordAuthEvent(ctx context.Context, success bool, userID uint, ip string, deviceFingerprint string) {
	if success {
		s.authSuccessCount++
	} else {
		s.authFailureCount++
	}

	if (s.authSuccessCount+s.authFailureCount)%10 == 0 {
		s.calculateAuthSuccessRate(ctx)
	}

	eventType := "auth_success"
	status := "success"
	if !success {
		eventType = "auth_failure"
		status = "failure"
	}
	service.GetAuditService().LogEvent(eventType, userID, "", ip, "", fmt.Sprintf("用户 %d 认证%s", userID, map[bool]string{true: "成功", false: "失败"}[success]), status)

}

func (s *monitorServiceImpl) RecordTokenEvent(ctx context.Context, eventType string, userID uint, clientID string, ip string) {
	switch eventType {
	case "issued":
		s.tokenIssuedCount++
	case "revoked":
		s.tokenRevokedCount++
	}

	if (s.tokenIssuedCount+s.tokenRevokedCount)%10 == 0 {
		s.recordTokenMetrics(ctx)
	}

	service.GetAuditService().LogEvent(fmt.Sprintf("token_%s", eventType), userID, "", ip, "", fmt.Sprintf("用户 %d 令牌%s", userID, map[string]string{"issued": "颁发", "revoked": "撤销"}[eventType]), "success")

}

func (s *monitorServiceImpl) DetectAnomaly(ctx context.Context, eventType string, userID uint, ip string, deviceFingerprint string, details map[string]interface{}) (bool, string) {
	switch eventType {
	case "login":
		return s.detectLoginAnomaly(ctx, userID, ip, deviceFingerprint, details)
	case "token":
		return s.detectTokenAnomaly(ctx, userID, ip, details)
	case "behavior":
		return s.detectBehaviorAnomaly(ctx, userID, details)
	default:
		return false, "未知事件类型"
	}
}

func (s *monitorServiceImpl) GetSystemStatus(ctx context.Context) (map[string]interface{}, error) {
	s.CollectSystemMetrics(ctx)

	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute)

	metrics, err := dao.GetMonitorDao().GetMetricsByType("system", startTime, endTime, 10)
	if err != nil {
		return nil, err
	}

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

func (s *monitorServiceImpl) GetAuthMetrics(ctx context.Context, startTime, endTime time.Time) ([]*model.MonitorMetric, error) {
	return dao.GetMonitorDao().GetMetricsByType("auth", startTime, endTime, 100)
}

func (s *monitorServiceImpl) GetTokenMetrics(ctx context.Context, startTime, endTime time.Time) ([]*model.MonitorMetric, error) {
	return dao.GetMonitorDao().GetMetricsByType("token", startTime, endTime, 100)
}

func (s *monitorServiceImpl) GetAnomalyEvents(ctx context.Context, startTime, endTime time.Time, severity string) ([]*model.AnomalyEvent, error) {
	return dao.GetMonitorDao().GetAnomalyEvents(startTime, endTime, severity, 100)
}

func (s *monitorServiceImpl) calculateAuthSuccessRate(ctx context.Context) {
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

func (s *monitorServiceImpl) recordTokenMetrics(ctx context.Context) {
	s.recordMetric(ctx, "token", "issued_count", float64(s.tokenIssuedCount), map[string]string{})

	s.recordMetric(ctx, "token", "revoked_count", float64(s.tokenRevokedCount), map[string]string{})
}

func (s *monitorServiceImpl) recordMetric(ctx context.Context, metricType, metricName string, value float64, labels map[string]string) {
	labelsJSON, _ := json.Marshal(labels)

	metric := &model.MonitorMetric{
		MetricType:  metricType,
		MetricName:  metricName,
		MetricValue: value,
		Labels:      string(labelsJSON),
		Timestamp:   time.Now(),
	}

	_, err := dao.GetMonitorDao().CreateMetric(metric)
	if err != nil {
		logger.Errorf(ctx, "记录监控指标失败: %v", err)
	}
}

func (s *monitorServiceImpl) detectLoginAnomaly(ctx context.Context, userID uint, ip string, deviceFingerprint string, details map[string]interface{}) (bool, string) {
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

func (s *monitorServiceImpl) detectTokenAnomaly(ctx context.Context, userID uint, ip string, details map[string]interface{}) (bool, string) {
	tokenRefreshes, ok := details["token_refreshes"].(int)
	if ok && tokenRefreshes > 10 {
		description := fmt.Sprintf("用户 %d 在短时间内令牌刷新 %d 次", userID, tokenRefreshes)
		s.createAnomalyEvent(ctx, "token_anomaly", "medium", description, userID, ip, "")
		return true, description
	}

	return false, ""
}

func (s *monitorServiceImpl) detectBehaviorAnomaly(ctx context.Context, userID uint, details map[string]interface{}) (bool, string) {
	operationCount, ok := details["operation_count"].(int)
	if ok && operationCount > 50 {
		description := fmt.Sprintf("用户 %d 在短时间内操作 %d 次，可能存在异常", userID, operationCount)
		s.createAnomalyEvent(ctx, "behavior_anomaly", "low", description, userID, "", "")
		return true, description
	}

	return false, ""
}

func (s *monitorServiceImpl) createAnomalyEvent(ctx context.Context, eventType, severity, description string, userID uint, ip, deviceFingerprint string) {
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

	_, err := dao.GetMonitorDao().CreateAnomalyEvent(event)
	if err != nil {
		logger.Errorf(ctx, "创建异常事件失败: %v", err)
	}

	service.GetAuditService().LogEvent("security_anomaly", userID, "", ip, "", description, "warning")

}
