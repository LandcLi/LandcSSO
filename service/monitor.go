package service

import (
	"context"
	"time"

	"github.com/LandcLi/LandcSSO/model"
)

type monitorService interface {
	CollectSystemMetrics(ctx context.Context) error
	RecordAuthEvent(ctx context.Context, success bool, userID uint, ip string, deviceFingerprint string)
	RecordTokenEvent(ctx context.Context, eventType string, userID uint, clientID string, ip string)
	DetectAnomaly(ctx context.Context, eventType string, userID uint, ip string, deviceFingerprint string, details map[string]interface{}) (bool, string)
	GetSystemStatus(ctx context.Context) (map[string]interface{}, error)
	GetAuthMetrics(ctx context.Context, startTime, endTime time.Time) ([]*model.MonitorMetric, error)
	GetTokenMetrics(ctx context.Context, startTime, endTime time.Time) ([]*model.MonitorMetric, error)
	GetAnomalyEvents(ctx context.Context, startTime, endTime time.Time, severity string) ([]*model.AnomalyEvent, error)
}

var monitorServiceImpl monitorService

func RegisterMonitorServiceImpl(impl monitorService) {
	monitorServiceImpl = impl
}

func GetMonitorService() monitorService {
	return monitorServiceImpl
}
