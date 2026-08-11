package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestThirdPartyCallbackInvalidState(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/auth/callback/:provider", ThirdPartyCallbackHandler)

	tests := []struct {
		name   string
		query  string
		expect string
	}{
		{"无 state", "/auth/callback/github?code=abc", "error=invalid_state"},
		{"错误 state", "/auth/callback/github?code=abc&state=deadbeef", "error=invalid_state"},
		{"state 与 provider 不匹配", "/auth/callback/github?code=abc&state=github-state", "error=invalid_state"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.query, nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusFound {
				t.Fatalf("期望 302, 实际 %d", w.Code)
			}
			location := w.Header().Get("Location")
			if !strings.Contains(location, tc.expect) {
				t.Errorf("Location=%q 应包含 %q", location, tc.expect)
			}
		})
	}
}
