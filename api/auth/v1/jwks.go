package v1

type JWKSResponse struct {
	Keys []Key `json:"keys"`
}
type Key struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}
