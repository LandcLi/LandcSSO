package v1

// UpdateProfileRequest 更新用户资料请求结构
type UpdateProfileRequest struct {
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Phone    string `json:"phone"`
}
