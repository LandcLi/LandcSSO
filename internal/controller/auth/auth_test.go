package auth

import "testing"

func TestIsRedirectURIRegistered(t *testing.T) {
	registered := `["http://localhost:3000/callback","https://app.example.com/cb"]`

	testCases := []struct {
		name         string
		registered   string
		redirectURI  string
		expectResult bool
	}{
		{"命中注册列表", registered, "http://localhost:3000/callback", true},
		{"命中第二个注册项", registered, "https://app.example.com/cb", true},
		{"未注册的URI", registered, "https://evil.com/callback", false},
		{"路径不一致", registered, "http://localhost:3000/other", false},
		{"空注册列表", "", "http://localhost:3000/callback", false},
		{"空URI", registered, "", false},
		{"非法JSON", "not-json", "http://localhost:3000/callback", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isRedirectURIRegistered(tc.registered, tc.redirectURI)
			if result != tc.expectResult {
				t.Errorf("isRedirectURIRegistered() = %v, 期望 %v", result, tc.expectResult)
			}
		})
	}
}
