package v1

// IntrospectRequest 令牌验证请求结构
type IntrospectRequest struct {
	Token        string `json:"token" binding:"required"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// IntrospectResponse 令牌验证响应结构
type IntrospectResponse struct {
	Active     bool   `json:"active"`
	Scope      string `json:"scope,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	UserID     uint   `json:"user_id,omitempty"`
	Username   string `json:"username,omitempty"`
	TokenType  string `json:"token_type,omitempty"`
	Exp        int64  `json:"exp,omitempty"`
	Iat        int64  `json:"iat,omitempty"`
	Nbf        int64  `json:"nbf,omitempty"`
	Iss        string `json:"iss,omitempty"`
	Sub        uint   `json:"sub,omitempty"`
	Aud        string `json:"aud,omitempty"`
}
