package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type RefreshTokenRequest struct {
	meta.Meta    `path:"/auth/refresh-token" method:"POST"`
	RefreshToken string `json:"refresh_token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}
