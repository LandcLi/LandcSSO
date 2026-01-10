package sdk

// Config SDK配置
type Config struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Issuer       string `json:"issuer"`
	Scope        string `json:"scope"`
}

// TokenResponse 令牌响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// IntrospectResponse 令牌验证响应
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
}

// UserInfoResponse 用户信息响应
type UserInfoResponse struct {
	Sub       string `json:"sub"`
	Name      string `json:"name,omitempty"`
	GivenName string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	MiddleName string `json:"middle_name,omitempty"`
	Nickname  string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile   string `json:"profile,omitempty"`
	Picture   string `json:"picture,omitempty"`
	Website   string `json:"website,omitempty"`
	Email     string `json:"email,omitempty"`
	EmailVerified bool `json:"email_verified,omitempty"`
	Gender    string `json:"gender,omitempty"`
	Birthdate string `json:"birthdate,omitempty"`
	Zoneinfo  string `json:"zoneinfo,omitempty"`
	Locale    string `json:"locale,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	Address   Address `json:"address,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// Address 地址信息
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// ErrorResponse 错误响应
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}
