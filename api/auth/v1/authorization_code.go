package v1

// AuthorizationCodeRequest 授权码请求结构
type AuthorizationCodeRequest struct {
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	ResponseType        string `json:"response_type" binding:"required"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state" binding:"required"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}
type AuthorizationCodeResponse struct {
	RedirectURI string `json:"redirect_uri"`
	Code        string `json:"code"`
	State       string `json:"state"`
}

// ValidateAuthorizationCodeRequest 验证授权码请求结构
type ValidateAuthorizationCodeRequest struct {
	Code         string `json:"code" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	CodeVerifier string `json:"code_verifier"`
}

// GenerateAuthCodeResponse 生成授权码响应结构
type GenerateAuthCodeResponse struct {
	Code string `json:"code"`
}
