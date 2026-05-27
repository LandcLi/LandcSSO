package v1

// ClientCreateRequest 创建客户端请求
type ClientCreateRequest struct {
	Name                    string   `json:"name" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}
