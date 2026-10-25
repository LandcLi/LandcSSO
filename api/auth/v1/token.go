package v1

import "github.com/LandcLi/landc-go/frame/pkg/meta"

type TokenRequest struct {
	meta.Meta    `path:"/auth/token" method:"POST"`
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Scope        string `json:"scope"`
	CodeVerifier string `json:"code_verifier"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	IsTmp        bool   `json:"is_tmp"`
}
