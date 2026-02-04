package v1

// ThirdPartyAuthURLRequest 获取第三方认证链接请求结构
type ThirdPartyAuthURLRequest struct {
	Provider    string            `json:"provider" binding:"required"` // 第三方提供商，如"wechat"
	RedirectURI string            `json:"redirect_uri" binding:"required"`
	State       string            `json:"state"`
	Scope       string            `json:"scope"`
	Params      map[string]string `json:"params"` // 额外参数
}

// ThirdPartyAuthURLResponse 获取第三方认证链接响应结构
type ThirdPartyAuthURLResponse struct {
	AuthURL string `json:"auth_url"`
}
