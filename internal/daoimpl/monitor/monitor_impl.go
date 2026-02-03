package monitor

import (
	"time"

	"github.com/LandcLi/LandcSSO/dao"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/LandcSSO/utility/config"
	"gorm.io/gorm"
)

type monitorDaoImpl struct {
	db *gorm.DB
}

func NewMonitorDaoImpl() *monitorDaoImpl {
	return &monitorDaoImpl{
		db: config.GetDB(),
	}
}

func init() {
	if dao.GetMonitorDao() == nil {
		dao.RegisterMonitorDaoImpl(NewMonitorDaoImpl())
	}
}

func (r *monitorDaoImpl) CreateMetric(metric *model.MonitorMetric) (*model.MonitorMetric, error) {
	result := r.db.Create(metric)
	return metric, result.Error
}

func (r *monitorDaoImpl) GetMetricsByType(metricType string, startTime, endTime time.Time, limit int) ([]*model.MonitorMetric, error) {
	var metrics []*model.MonitorMetric
	result := r.db.Where("metric_type = ? AND timestamp BETWEEN ? AND ?", metricType, startTime, endTime).Order("timestamp DESC").Limit(limit).Find(&metrics)
	return metrics, result.Error
}

func (r *monitorDaoImpl) GetMetricsByName(metricName string, startTime, endTime time.Time, limit int) ([]*model.MonitorMetric, error) {
	var metrics []*model.MonitorMetric
	result := r.db.Where("metric_name = ? AND timestamp BETWEEN ? AND ?", metricName, startTime, endTime).Order("timestamp DESC").Limit(limit).Find(&metrics)
	return metrics, result.Error
}

func (r *monitorDaoImpl) CreateAnomalyEvent(event *model.AnomalyEvent) (*model.AnomalyEvent, error) {
	result := r.db.Create(event)
	return event, result.Error
}

func (r *monitorDaoImpl) GetAnomalyEvents(startTime, endTime time.Time, severity string, limit int) ([]*model.AnomalyEvent, error) {
	var events []*model.AnomalyEvent
	query := r.db.Where("timestamp BETWEEN ? AND ?", startTime, endTime)
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	result := query.Order("timestamp DESC").Limit(limit).Find(&events)
	return events, result.Error
}

func (r *monitorDaoImpl) GetAnomalyEventsByUser(userID uint, startTime, endTime time.Time, limit int) ([]*model.AnomalyEvent, error) {
	var events []*model.AnomalyEvent
	result := r.db.Where("user_id = ? AND timestamp BETWEEN ? AND ?", userID, startTime, endTime).Order("timestamp DESC").Limit(limit).Find(&events)
	return events, result.Error
}

func (r *monitorDaoImpl) UpdateAnomalyEventStatus(eventID uint, status string) error {
	result := r.db.Model(&model.AnomalyEvent{}).Where("id = ?", eventID).Update("status", status)
	return result.Error
}
