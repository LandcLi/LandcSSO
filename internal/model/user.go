package model

import (
	"time"
)

// User 用户模型
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Username  string    `json:"username" gorm:"uniqueIndex;size:50;not null"`
	Email     string    `json:"email" gorm:"uniqueIndex;size:100;not null"`
	Password  string    `json:"-" gorm:"size:100;not null"`
	Nickname  string    `json:"nickname" gorm:"size:50"`
	Avatar    string    `json:"avatar" gorm:"size:255"`
	Phone     string    `json:"phone" gorm:"size:20"`
	Status    int       `json:"status" gorm:"default:1"` // 1: 活跃, 0: 禁用
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserLoginRequest 登录请求
type UserLoginRequest struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RememberMe bool   `json:"rememberMe" binding:"omitempty"`
}

// VerifyCodeRequest 验证码请求
type VerifyCodeRequest struct {
	Email  string `json:"email" binding:"omitempty,email"`
	Phone  string `json:"phone" binding:"omitempty,max=20"`
	Action string `json:"action" binding:"required,oneof=login register"`
}

// VerifyCodeLoginRequest 验证码登录请求
type VerifyCodeLoginRequest struct {
	Email      string `json:"email" binding:"omitempty,email"`
	Phone      string `json:"phone" binding:"omitempty,max=20"`
	VerifyCode string `json:"verifyCode" binding:"required,len=6"`
}

// ThirdPartyLoginRequest 第三方登录请求
type ThirdPartyLoginRequest struct {
	Provider string `json:"provider" binding:"required,oneof=wechat dingtalk github"`
	Code     string `json:"code" binding:"required"`
	State    string `json:"state" binding:"required"`
}

// ThirdPartyUser 第三方用户信息
type ThirdPartyUser struct {
	Provider string `json:"provider"`
	OpenID   string `json:"openId"`
	UnionID  string `json:"unionId"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Gender   string `json:"gender"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
}

// UserRegisterRequest 注册请求
type UserRegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Nickname string `json:"nickname" binding:"max=50"`
	Phone    string `json:"phone" binding:"max=20"`
}

// UserResponse 用户响应
type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Phone    string `json:"phone"`
	Status   int    `json:"status"`
}

// ToResponse 转换为响应对象
func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:       u.ID,
		Username: u.Username,
		Email:    u.Email,
		Nickname: u.Nickname,
		Avatar:   u.Avatar,
		Phone:    u.Phone,
		Status:   u.Status,
	}
}

// ThirdPartyUserLink 第三方用户关联模型
type ThirdPartyUserLink struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	UserID    uint      `json:"userId" gorm:"index;not null"`
	Provider  string    `json:"provider" gorm:"size:50;not null"`
	OpenID    string    `json:"openId" gorm:"size:100;not null"`
	UnionID   string    `json:"unionId" gorm:"size:100"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// TableName 指定表名
func (ThirdPartyUserLink) TableName() string {
	return "third_party_user_links"
}

// TrustedDevice 信任设备模型
type TrustedDevice struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	UserID            uint      `json:"userId" gorm:"index;not null"`
	DeviceFingerprint string    `json:"deviceFingerprint" gorm:"size:255;not null"`
	DeviceName        string    `json:"deviceName" gorm:"size:100"`
	LastLoginIP       string    `json:"lastLoginIp" gorm:"size:50"`
	FirstLoginTime    time.Time `json:"firstLoginTime"`
	LastLoginTime     time.Time `json:"lastLoginTime"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// TableName 指定表名
func (TrustedDevice) TableName() string {
	return "trusted_devices"
}
