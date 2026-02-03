package v1

// ChangePasswordRequest 修改密码请求结构
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required,min=6,max=100"`
	NewPassword string `json:"new_password" binding:"required,min=6,max=100"`
}
