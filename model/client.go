package model

import (
	"encoding/json"
	"time"

	v1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/landc-go/log/facade"
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
	// 三个字段在库里以 JSON 数组字符串存储。解析失败时按空列表返回，
	// 但必须留痕 —— 静默吞掉会让「客户端登录后跳转异常」无从排查：
	// 表现只是回调地址莫名其妙变空，DB 里却是脏数据。
	var redirectURIs []string
	if c.RedirectURIs != "" {
		if err := json.Unmarshal([]byte(c.RedirectURIs), &redirectURIs); err != nil {
			facade.Warnf("client %s 的 redirect_uris 解析失败，按空处理: %v", c.ClientID, err)
		}
	}

	// 解析GrantTypes
	var grantTypes []string
	if c.GrantTypes != "" {
		if err := json.Unmarshal([]byte(c.GrantTypes), &grantTypes); err != nil {
			facade.Warnf("client %s 的 grant_types 解析失败，按空处理: %v", c.ClientID, err)
		}
	}

	// 解析ResponseTypes
	var responseTypes []string
	if c.ResponseTypes != "" {
		if err := json.Unmarshal([]byte(c.ResponseTypes), &responseTypes); err != nil {
			facade.Warnf("client %s 的 response_types 解析失败，按空处理: %v", c.ClientID, err)
		}
	}

	return &v1.ClientResponse{
		ID:                      c.ID,
		ClientID:                c.ClientID,
		ClientSecret:            "", // 密钥哈希不对外返回；仅在创建时返回一次明文
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
