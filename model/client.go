package model

import (
	"encoding/json"
	"time"

	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
)

// Client 客户端模型
type Client struct {
	ID                      uint      `json:"id" gorm:"primaryKey"`
	ClientID                string    `json:"client_id" gorm:"uniqueIndex;size:100"`
	ClientSecret            string    `json:"client_secret" gorm:"size:255"`
	Name                    string    `json:"name" gorm:"size:100"`
	RedirectURIs            string    `json:"redirect_uris" gorm:"size:1000"` // JSON格式存储
	Scope                   string    `json:"scope" gorm:"size:255"`
	GrantTypes              string    `json:"grant_types" gorm:"size:255"`    // JSON格式存储
	ResponseTypes           string    `json:"response_types" gorm:"size:255"` // JSON格式存储
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method" gorm:"size:50"`
	Status                  int       `json:"status" gorm:"default:1"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// TableName 指定表名
func (Client) TableName() string {
	return "clients"
}

// ToResponse 转换为响应
func (c *Client) ToResponse() *v1.ClientResponse {
	// 解析RedirectURIs
	var redirectURIs []string
	if c.RedirectURIs != "" {
		json.Unmarshal([]byte(c.RedirectURIs), &redirectURIs)
	}

	// 解析GrantTypes
	var grantTypes []string
	if c.GrantTypes != "" {
		json.Unmarshal([]byte(c.GrantTypes), &grantTypes)
	}

	// 解析ResponseTypes
	var responseTypes []string
	if c.ResponseTypes != "" {
		json.Unmarshal([]byte(c.ResponseTypes), &responseTypes)
	}

	return &v1.ClientResponse{
		ID:                      c.ID,
		ClientID:                c.ClientID,
		ClientSecret:            c.ClientSecret,
		Name:                    c.Name,
		RedirectURIs:            redirectURIs,
		Scope:                   c.Scope,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		Status:                  c.Status,
		CreatedAt:               c.CreatedAt,
	}
}
