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
	Sub                 string  `json:"sub"`
	Name                string  `json:"name,omitempty"`
	GivenName           string  `json:"given_name,omitempty"`
	FamilyName          string  `json:"family_name,omitempty"`
	MiddleName          string  `json:"middle_name,omitempty"`
	Nickname            string  `json:"nickname,omitempty"`
	PreferredUsername   string  `json:"preferred_username,omitempty"`
	Profile             string  `json:"profile,omitempty"`
	Picture             string  `json:"picture,omitempty"`
	Website             string  `json:"website,omitempty"`
	Email               string  `json:"email,omitempty"`
	EmailVerified       bool    `json:"email_verified,omitempty"`
	Gender              string  `json:"gender,omitempty"`
	Birthdate           string  `json:"birthdate,omitempty"`
	Zoneinfo            string  `json:"zoneinfo,omitempty"`
	Locale              string  `json:"locale,omitempty"`
	PhoneNumber         string  `json:"phone_number,omitempty"`
	PhoneNumberVerified bool    `json:"phone_number_verified,omitempty"`
	Address             Address `json:"address,omitempty"`
	UpdatedAt           int64   `json:"updated_at,omitempty"`
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

// ThirdPartyLoginRequest 第三方登录请求
type ThirdPartyLoginRequest struct {
	Provider string `json:"provider"`
	Code     string `json:"code"`
	State    string `json:"state"`
}

// BiometricLoginRequest 生物识别登录请求
type BiometricLoginRequest struct {
	UserID            string `json:"user_id"`
	DeviceFingerprint string `json:"device_fingerprint"`
	BiometricData     string `json:"biometric_data"`
}

// ScanCodeLoginRequest 扫码登录请求
type ScanCodeLoginRequest struct {
	ClientID string `json:"client_id"`
}

// ScanCodeVerifyRequest 扫码验证请求
type ScanCodeVerifyRequest struct {
	Code   string `json:"code"`
	UserID string `json:"user_id"`
}

// ScanCodeStatusRequest 扫码状态请求
type ScanCodeStatusRequest struct {
	Code string `json:"code"`
}

// ScanCodeCompleteRequest 扫码完成请求
type ScanCodeCompleteRequest struct {
	Code string `json:"code"`
}

// ScanCodeLoginResponse 扫码登录响应
type ScanCodeLoginResponse struct {
	Code   string `json:"code"`
	QRCode string `json:"qrcode"`
}

// ScanCodeStatusResponse 扫码状态响应
type ScanCodeStatusResponse struct {
	Status        string         `json:"status"`
	TokenResponse *TokenResponse `json:"token_response,omitempty"`
}

// DeviceInfo 设备信息
type DeviceInfo struct {
	ID                string `json:"id"`
	UserID            string `json:"user_id"`
	DeviceFingerprint string `json:"device_fingerprint"`
	DeviceName        string `json:"device_name"`
	DeviceType        string `json:"device_type"`
	LastLoginIP       string `json:"last_login_ip"`
	LastLoginTime     string `json:"last_login_time"`
	IsTrusted         bool   `json:"is_trusted"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// AuditLogEntry 审计日志条目
type AuditLogEntry struct {
	ID        string `json:"id"`
	EventType string `json:"event_type"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Details   string `json:"details"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// SystemStatusResponse 系统状态响应
type SystemStatusResponse struct {
	System struct {
		CPU    float64 `json:"cpu"`
		Memory float64 `json:"memory"`
		Disk   float64 `json:"disk"`
	} `json:"system"`
	Services struct {
		MySQL string `json:"mysql"`
		Redis string `json:"redis"`
		SSO   string `json:"sso"`
	} `json:"services"`
	Metrics struct {
		AuthSuccessRate   float64 `json:"auth_success_rate"`
		AuthLatency       float64 `json:"auth_latency"`
		TokenIssuanceRate float64 `json:"token_issuance_rate"`
	} `json:"metrics"`
}

// MetricEntry 指标条目
type MetricEntry struct {
	Name      string  `json:"name"`
	Value     float64 `json:"value"`
	Timestamp string  `json:"timestamp"`
}

// AnomalyEvent 异常事件
type AnomalyEvent struct {
	ID                string `json:"id"`
	EventType         string `json:"event_type"`
	Severity          string `json:"severity"`
	Description       string `json:"description"`
	UserID            string `json:"user_id"`
	IP                string `json:"ip"`
	DeviceFingerprint string `json:"device_fingerprint"`
	Status            string `json:"status"`
	Timestamp         string `json:"timestamp"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}
