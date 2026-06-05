package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type RevokeTokenRequest struct {
	meta.Meta    `path:"/auth/revoke-token" method:"POST"`
	Token        string `json:"token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
