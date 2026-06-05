package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type AuthorizationCodeRequest struct {
	meta.Meta           `path:"/auth/authorize" method:"POST"`
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

type ValidateAuthorizationCodeRequest struct {
	meta.Meta    `path:"/auth/verify-auth-code" method:"POST"`
	Code         string `json:"code" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	CodeVerifier string `json:"code_verifier"`
}

type GenerateAuthCodeResponse struct {
	Code string `json:"code"`
}
