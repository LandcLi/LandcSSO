package model

import (
	"encoding/json"
	"time"
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

// ClientResponse 客户端响应
type ClientResponse struct {
	ID                      uint      `json:"id"`
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret"`
	Name                    string    `json:"name"`
	RedirectURIs            []string  `json:"redirect_uris"`
	Scope                   string    `json:"scope"`
	GrantTypes              []string  `json:"grant_types"`
	ResponseTypes           []string  `json:"response_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	Status                  int       `json:"status"`
	CreatedAt               time.Time `json:"created_at"`
}

// ClientListRequest 客户端列表请求
type ClientListRequest struct {
	Page     int `json:"page" form:"page" binding:"min=1"`
	PageSize int `json:"page_size" form:"page_size" binding:"min=1,max=100"`
}

// ClientCreateRequest 创建客户端请求
type ClientCreateRequest struct {
	Name                    string   `json:"name" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// ClientUpdateRequest 更新客户端请求
type ClientUpdateRequest struct {
	ID                      uint     `json:"id" binding:"required"`
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Status                  int      `json:"status"`
}

// ClientDeleteRequest 删除客户端请求
type ClientDeleteRequest struct {
	ID uint `json:"id" binding:"required"`
}

// ClientListResponse 客户端列表响应
type ClientListResponse struct {
	List     []ClientResponse `json:"list"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// ToResponse 转换为响应
func (c *Client) ToResponse() *ClientResponse {
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

	return &ClientResponse{
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
