package repository

import (
	"time"

	"github.com/LandcLi/LandcBranchGorm/pkg/dbmanager"
	"github.com/LandcLi/LandcSSO/internal/model"
)

// MonitorRepository 监控仓库
type MonitorRepository struct {
	dbmanager *dbmanager.DBManager
}

// NewMonitorRepository 创建监控仓库实例
func NewMonitorRepository(dbmanager *dbmanager.DBManager) *MonitorRepository {
	return &MonitorRepository{
		dbmanager: dbmanager,
	}
}

// CreateMetric 创建监控指标
func (r *MonitorRepository) CreateMetric(metric *model.MonitorMetric) (*model.MonitorMetric, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	result := db.Create(metric)
	return metric, result.Error
}

// GetMetricsByType 根据指标类型获取监控指标
func (r *MonitorRepository) GetMetricsByType(metricType string, startTime, endTime time.Time, limit int) ([]*model.MonitorMetric, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var metrics []*model.MonitorMetric
	result := db.Where("metric_type = ? AND timestamp BETWEEN ? AND ?", metricType, startTime, endTime).Order("timestamp DESC").Limit(limit).Find(&metrics)
	return metrics, result.Error
}

// GetMetricsByName 根据指标名称获取监控指标
func (r *MonitorRepository) GetMetricsByName(metricName string, startTime, endTime time.Time, limit int) ([]*model.MonitorMetric, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var metrics []*model.MonitorMetric
	result := db.Where("metric_name = ? AND timestamp BETWEEN ? AND ?", metricName, startTime, endTime).Order("timestamp DESC").Limit(limit).Find(&metrics)
	return metrics, result.Error
}

// CreateAnomalyEvent 创建异常事件
func (r *MonitorRepository) CreateAnomalyEvent(event *model.AnomalyEvent) (*model.AnomalyEvent, error) {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return nil, err
	}
	result := db.Create(event)
	return event, result.Error
}

// GetAnomalyEvents 获取异常事件列表
func (r *MonitorRepository) GetAnomalyEvents(startTime, endTime time.Time, severity string, limit int) ([]*model.AnomalyEvent, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var events []*model.AnomalyEvent
	query := db.Where("timestamp BETWEEN ? AND ?", startTime, endTime)
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	result := query.Order("timestamp DESC").Limit(limit).Find(&events)
	return events, result.Error
}

// GetAnomalyEventsByUser 根据用户ID获取异常事件
func (r *MonitorRepository) GetAnomalyEventsByUser(userID uint, startTime, endTime time.Time, limit int) ([]*model.AnomalyEvent, error) {
	db, err := r.dbmanager.GetDB("sso_db", false)
	if err != nil {
		db, err = r.dbmanager.GetDB("sso_db", true)
		if err != nil {
			return nil, err
		}
	}
	var events []*model.AnomalyEvent
	result := db.Where("user_id = ? AND timestamp BETWEEN ? AND ?", userID, startTime, endTime).Order("timestamp DESC").Limit(limit).Find(&events)
	return events, result.Error
}

// UpdateAnomalyEventStatus 更新异常事件状态
func (r *MonitorRepository) UpdateAnomalyEventStatus(eventID uint, status string) error {
	db, err := r.dbmanager.GetDB("sso_db", true)
	if err != nil {
		return err
	}
	result := db.Model(&model.AnomalyEvent{}).Where("id = ?", eventID).Update("status", status)
	return result.Error
}
