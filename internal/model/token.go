package model

import (
	"time"
)

// Token 令牌模型
type Token struct {
	ID                uint      `json:"id" gorm:"primaryKey"`
	UserID            uint      `json:"user_id" gorm:"index;not null"`
	AccessToken       string    `json:"access_token" gorm:"size:500;not null"`
	RefreshToken      string    `json:"refresh_token" gorm:"size:500;not null"`
	ExpiresAt         time.Time `json:"expires_at" gorm:"not null"`
	RefreshExpiresAt  time.Time `json:"refresh_expires_at" gorm:"not null"`
	ClientID          string    `json:"client_id" gorm:"size:100;index"`
	Scope             string    `json:"scope" gorm:"size:255"`
	Revoked           bool      `json:"revoked" gorm:"default:false"`
	IP                string    `json:"ip" gorm:"size:50"`
	DeviceFingerprint string    `json:"device_fingerprint" gorm:"size:255"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// AuthorizationCode 授权码模型
type AuthorizationCode struct {
	ID                  uint      `json:"id" gorm:"primaryKey"`
	Code                string    `json:"code" gorm:"size:255;uniqueIndex;not null"`
	UserID              uint      `json:"user_id" gorm:"index;not null"`
	ClientID            string    `json:"client_id" gorm:"size:100;index;not null"`
	RedirectURI         string    `json:"redirect_uri" gorm:"size:512;not null"`
	Scope               string    `json:"scope" gorm:"size:255"`
	State               string    `json:"state" gorm:"size:255"`
	Nonce               string    `json:"nonce" gorm:"size:255"`
	CodeChallenge       string    `json:"code_challenge" gorm:"size:255"`
	CodeChallengeMethod string    `json:"code_challenge_method" gorm:"size:50"`
	ExpiresAt           time.Time `json:"expires_at" gorm:"not null"`
	Used                bool      `json:"used" gorm:"default:false"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// TokenRequest 令牌请求
type TokenRequest struct {
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenResponse 令牌响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Claims JWT声明
type Claims struct {
	UserID            uint   `json:"user_id"`
	Username          string `json:"username"`
	Email             string `json:"email"`
	Scope             string `json:"scope"`
	ClientID          string `json:"client_id"`
	IP                string `json:"ip"`
	DeviceFingerprint string `json:"device_fingerprint"`
}
