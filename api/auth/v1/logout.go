package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type LogoutRequest struct {
	meta.Meta `path:"/auth/logout" method:"POST"`
	Token     string `json:"token"`
	ClientID  string `json:"client_id"`
}
