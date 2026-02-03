package dao

import (
	"time"

	"github.com/LandcLi/LandcSSO/model"
)

type monitorDao interface {
	CreateMetric(metric *model.MonitorMetric) (*model.MonitorMetric, error)
	GetMetricsByType(metricType string, startTime, endTime time.Time, limit int) ([]*model.MonitorMetric, error)
	GetMetricsByName(metricName string, startTime, endTime time.Time, limit int) ([]*model.MonitorMetric, error)
	CreateAnomalyEvent(event *model.AnomalyEvent) (*model.AnomalyEvent, error)
	GetAnomalyEvents(startTime, endTime time.Time, severity string, limit int) ([]*model.AnomalyEvent, error)
	GetAnomalyEventsByUser(userID uint, startTime, endTime time.Time, limit int) ([]*model.AnomalyEvent, error)
	UpdateAnomalyEventStatus(eventID uint, status string) error
}

var monitorDaoImpl monitorDao

func RegisterMonitorDaoImpl(impl monitorDao) {
	monitorDaoImpl = impl
}

func GetMonitorDao() monitorDao {
	return monitorDaoImpl
}
