package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type ThirdPartyAuthURLRequest struct {
	meta.Meta    `path:"/auth/third-party-login" method:"POST"`
	Provider    string            `json:"provider" binding:"required"`
	RedirectURI string            `json:"redirect_uri" binding:"required"`
	State       string            `json:"state"`
	Scope       string            `json:"scope"`
	Params      map[string]string `json:"params"`
}

type ThirdPartyAuthURLResponse struct {
	AuthURL string `json:"auth_url"`
	// State SSO 服务端生成的 CSRF 防伪 state，回调登录时必须原样传回
	State string `json:"state"`
}
