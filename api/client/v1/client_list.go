package v1

import (
	"time"

	"github.com/LandcLi/landc-go/frame/pkg/meta"
)

type ClientListRequest struct {
	meta.Meta `path:"/client/list" method:"GET"`
	Page      int `json:"page" form:"page" binding:"min=1"`
	PageSize  int `json:"page_size" form:"page_size" binding:"min=1,max=100"`
}

type ClientListResponse struct {
	List     []ClientResponse `json:"list"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

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
