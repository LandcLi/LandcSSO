package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type ClientUpdateRequest struct {
	meta.Meta               `path:"/client/update" method:"PUT"`
	ID                      uint     `json:"id" binding:"required"`
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scope                   string   `json:"scope"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Status                  int      `json:"status"`
}
