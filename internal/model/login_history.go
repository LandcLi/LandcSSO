package model

import (
	"time"
)

// LoginHistory 登录历史记录模型
type LoginHistory struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	UserID            uint      `json:"user_id" gorm:"index;not null"`
	IP                string    `json:"ip" gorm:"size:50;not null"`
	DeviceFingerprint string    `json:"device_fingerprint" gorm:"size:255"`
	UserAgent         string    `json:"user_agent" gorm:"size:255"`
	LoginTime         time.Time `json:"login_time" gorm:"not null"`
	Status            int       `json:"status" gorm:"default:1"` // 1: 成功, 0: 失败
	IsAbnormal        bool      `json:"is_abnormal" gorm:"default:false"`
	Remark            string    `json:"remark" gorm:"size:255"`
	CreatedAt         time.Time `json:"created_at"`
}

// LoginHistoryResponse 登录历史记录响应
type LoginHistoryResponse struct {
	ID                uint      `json:"id"`
	UserID            uint      `json:"user_id"`
	IP                string    `json:"ip"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UserAgent         string    `json:"user_agent"`
	LoginTime         time.Time `json:"login_time"`
	Status            int       `json:"status"`
	IsAbnormal        bool      `json:"is_abnormal"`
	Remark            string    `json:"remark"`
	CreatedAt         time.Time `json:"created_at"`
}

// ToResponse 转换为响应对象
func (l *LoginHistory) ToResponse() *LoginHistoryResponse {
	return &LoginHistoryResponse{
		ID:                l.ID,
		UserID:            l.UserID,
		IP:                l.IP,
		DeviceFingerprint: l.DeviceFingerprint,
		UserAgent:         l.UserAgent,
		LoginTime:         l.LoginTime,
		Status:            l.Status,
		IsAbnormal:        l.IsAbnormal,
		Remark:            l.Remark,
		CreatedAt:         l.CreatedAt,
	}
}
