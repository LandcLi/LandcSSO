package v1

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
