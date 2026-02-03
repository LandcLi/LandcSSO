package model

import (
	"time"
)

// AuditEvent 审计事件
type AuditEvent struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	EventType string    `json:"event_type" gorm:"size:50;not null"`
	UserID    uint      `json:"user_id" gorm:"index"`
	Username  string    `json:"username" gorm:"size:50"`
	IP        string    `json:"ip" gorm:"size:50"`
	UserAgent string    `json:"user_agent" gorm:"size:255"`
	Details   string    `json:"details" gorm:"type:text"`
	Status    string    `json:"status" gorm:"size:20;not null"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (AuditEvent) TableName() string {
	return "audit_events"
}
