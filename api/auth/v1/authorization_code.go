package v1

// AuthorizationCodeRequest 授权码请求结构
type AuthorizationCodeRequest struct {
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// ValidateAuthorizationCodeRequest 验证授权码请求结构
type ValidateAuthorizationCodeRequest struct {
	Code         string `json:"code" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	CodeVerifier string `json:"code_verifier"`
}
