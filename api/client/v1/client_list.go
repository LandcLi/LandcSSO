package v1

import "time"

// ClientListRequest 客户端列表请求
type ClientListRequest struct {
	Page     int `json:"page" form:"page" binding:"min=1"`
	PageSize int `json:"page_size" form:"page_size" binding:"min=1,max=100"`
}

// ClientListResponse 客户端列表响应
type ClientListResponse struct {
	List     []ClientResponse `json:"list"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
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
