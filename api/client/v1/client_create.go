package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type ClientCreateRequest struct {
	meta.Meta               `path:"/client/create" method:"POST"`
	Name                    string   `json:"name" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}
