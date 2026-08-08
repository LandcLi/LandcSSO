package third_party

import (
	"strings"
	"testing"
)

// TestGenerateState 验证 state 生成格式与随机性
func TestGenerateState(t *testing.T) {
	s1 := GenerateState("github")
	s2 := GenerateState("github")

	if len(s1) != 64 {
		t.Errorf("state 应为 64 位 hex 字符串, 实际长度 %d", len(s1))
	}
	if s1 == s2 {
		t.Error("两次生成的 state 不应相同")
	}
	// 应为 hex 字符
	if strings.ContainsAny(s1, "+/=") {
		t.Errorf("state 不应包含 URL 不安全字符: %s", s1)
	}
}

// TestValidateAndConsumeState 验证校验与一次性消费
func TestValidateAndConsumeState(t *testing.T) {
	state := GenerateState("github")

	// 正确 provider 校验通过
	if !ValidateAndConsumeState(state, "github") {
		t.Error("正确 state+provider 应校验通过")
	}
	// 一次性：重复消费失败
	if ValidateAndConsumeState(state, "github") {
		t.Error("state 已被消费，重复使用应失败")
	}
}

// TestValidateAndConsumeStateWrongProvider 验证 provider 不匹配拒绝
func TestValidateAndConsumeStateWrongProvider(t *testing.T) {
	state := GenerateState("github")

	if ValidateAndConsumeState(state, "alipay") {
		t.Error("provider 不匹配应拒绝")
	}
	// 不匹配消费后 state 应被清除（防重放）
	if ValidateAndConsumeState(state, "github") {
		t.Error("不匹配消费后 state 应被清除")
	}
}

// TestValidateAndConsumeStateEmpty 验证空 state 拒绝
func TestValidateAndConsumeStateEmpty(t *testing.T) {
	if ValidateAndConsumeState("", "github") {
		t.Error("空 state 应拒绝")
	}
	if ValidateAndConsumeState("nonexistent-state-12345", "github") {
		t.Error("不存在的 state 应拒绝")
	}
}
