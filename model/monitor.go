package model

import (
	"time"
)

// MonitorMetric 监控指标模型
type MonitorMetric struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	MetricType  string    `json:"metric_type" gorm:"index;size:50;not null"`  // 指标类型：system, auth, token, security
	MetricName  string    `json:"metric_name" gorm:"index;size:100;not null"` // 指标名称：cpu_usage, memory_usage, auth_success_rate, etc.
	MetricValue float64   `json:"metric_value" gorm:"not null"`               // 指标值
	Labels      string    `json:"labels" gorm:"size:255"`                     // 标签，JSON格式
	Timestamp   time.Time `json:"timestamp" gorm:"index;not null"`            // 时间戳
	CreatedAt   time.Time `json:"created_at"`
}

// TableName 指定表名
func (MonitorMetric) TableName() string {
	return "monitor_metrics"
}

// MonitorMetricResponse 监控指标响应
type MonitorMetricResponse struct {
	ID          uint      `json:"id"`
	MetricType  string    `json:"metric_type"`
	MetricName  string    `json:"metric_name"`
	MetricValue float64   `json:"metric_value"`
	Labels      string    `json:"labels"`
	Timestamp   time.Time `json:"timestamp"`
	CreatedAt   time.Time `json:"created_at"`
}

// ToResponse 转换为响应对象
func (m *MonitorMetric) ToResponse() *MonitorMetricResponse {
	return &MonitorMetricResponse{
		ID:          m.ID,
		MetricType:  m.MetricType,
		MetricName:  m.MetricName,
		MetricValue: m.MetricValue,
		Labels:      m.Labels,
		Timestamp:   m.Timestamp,
		CreatedAt:   m.CreatedAt,
	}
}

// AnomalyEvent 异常事件模型
type AnomalyEvent struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	EventType         string    `json:"event_type" gorm:"index;size:50;not null"` // 事件类型：login_anomaly, token_anomaly, behavior_anomaly
	Severity          string    `json:"severity" gorm:"size:20;not null"`         // 严重程度：low, medium, high
	Description       string    `json:"description" gorm:"size:255;not null"`     // 事件描述
	UserID            uint      `json:"user_id" gorm:"index"`                     // 关联的用户ID
	IP                string    `json:"ip" gorm:"size:50"`                        // 关联的IP地址
	DeviceFingerprint string    `json:"device_fingerprint" gorm:"size:255"`       // 关联的设备指纹
	Status            string    `json:"status" gorm:"size:20;default:'pending'"`  // 处理状态：pending, processed, ignored
	Timestamp         time.Time `json:"timestamp" gorm:"index;not null"`          // 时间戳
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AnomalyEvent) TableName() string {
	return "anomaly_events"
}

// AnomalyEventResponse 异常事件响应
type AnomalyEventResponse struct {
	ID                uint      `json:"id"`
	EventType         string    `json:"event_type"`
	Severity          string    `json:"severity"`
	Description       string    `json:"description"`
	UserID            uint      `json:"user_id"`
	IP                string    `json:"ip"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	Status            string    `json:"status"`
	Timestamp         time.Time `json:"timestamp"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// ToResponse 转换为响应对象
func (a *AnomalyEvent) ToResponse() *AnomalyEventResponse {
	return &AnomalyEventResponse{
		ID:                a.ID,
		EventType:         a.EventType,
		Severity:          a.Severity,
		Description:       a.Description,
		UserID:            a.UserID,
		IP:                a.IP,
		DeviceFingerprint: a.DeviceFingerprint,
		Status:            a.Status,
		Timestamp:         a.Timestamp,
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}
