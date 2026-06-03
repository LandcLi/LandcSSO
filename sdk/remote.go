package sdk

import (
	"context"

	"github.com/LandcLi/LandcSSO/api/auth"
	v1 "github.com/LandcLi/LandcSSO/api/auth/v1"
	clientApi "github.com/LandcLi/LandcSSO/api/client"
	clientV1 "github.com/LandcLi/LandcSSO/api/client/v1"
	"github.com/LandcLi/LandcSSO/model"
	"github.com/LandcLi/landc-go/frame/pkg/di"
)

// ============ Remote Auth Controller ============

// RemoteAuthController implements auth.AuthController via HTTP calls.
type RemoteAuthController struct {
	client *di.ProxyClient
}

// NewRemoteAuthController creates a remote auth controller.
//
//	remote := sdk.NewRemoteAuthController("http://sso:8080")
//	auth.AuthGateway.Override(remote)
func NewRemoteAuthController(baseURL string, opts ...di.RemoteOption) *RemoteAuthController {
	return &RemoteAuthController{
		client: di.NewProxyClient(baseURL, auth.AuthRoutes, opts...),
	}
}

func (r *RemoteAuthController) Login(ctx context.Context, req *v1.LoginRequest) (*v1.TokenResponse, error) {
	return di.Call[v1.TokenResponse](r.client, ctx, "Login", req)
}

func (r *RemoteAuthController) ExchangeTempToken(ctx context.Context, req *v1.ExchangeTempTokenRequest) (*v1.TokenResponse, error) {
	return di.Call[v1.TokenResponse](r.client, ctx, "ExchangeTempToken", req)
}

func (r *RemoteAuthController) RefreshToken(ctx context.Context, req *v1.RefreshTokenRequest) (*v1.TokenResponse, error) {
	return di.Call[v1.TokenResponse](r.client, ctx, "RefreshToken", req)
}

func (r *RemoteAuthController) RevokeToken(ctx context.Context, req *v1.RevokeTokenRequest) error {
	return di.CallVoid(r.client, ctx, "RevokeToken", req)
}

func (r *RemoteAuthController) Logout(ctx context.Context, req *v1.LogoutRequest) error {
	return di.CallVoid(r.client, ctx, "Logout", req)
}

func (r *RemoteAuthController) GenerateAuthorizationCode(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.GenerateAuthCodeResponse, error) {
	return di.Call[v1.GenerateAuthCodeResponse](r.client, ctx, "GenerateAuthorizationCode", req)
}

func (r *RemoteAuthController) ValidateAuthorizationCode(ctx context.Context, req *v1.ValidateAuthorizationCodeRequest) (*model.AuthorizationCode, error) {
	return di.Call[model.AuthorizationCode](r.client, ctx, "ValidateAuthorizationCode", req)
}

func (r *RemoteAuthController) GetThirdPartyAuthURL(ctx context.Context, req *v1.ThirdPartyAuthURLRequest) (*v1.ThirdPartyAuthURLResponse, error) {
	return di.Call[v1.ThirdPartyAuthURLResponse](r.client, ctx, "GetThirdPartyAuthURL", req)
}

func (r *RemoteAuthController) Authorize(ctx context.Context, req *v1.AuthorizationCodeRequest) (*v1.AuthorizationCodeResponse, error) {
	return di.Call[v1.AuthorizationCodeResponse](r.client, ctx, "Authorize", req)
}

func (r *RemoteAuthController) Token(ctx context.Context, req *v1.TokenRequest) (*v1.TokenResponse, error) {
	return di.Call[v1.TokenResponse](r.client, ctx, "Token", req)
}

func (r *RemoteAuthController) Introspect(ctx context.Context, req *v1.IntrospectRequest) (*v1.IntrospectResponse, error) {
	return di.Call[v1.IntrospectResponse](r.client, ctx, "Introspect", req)
}

func (r *RemoteAuthController) GetJWKS(ctx context.Context) (*v1.JWKSResponse, error) {
	return di.Call[v1.JWKSResponse](r.client, ctx, "GetJWKS", nil)
}

// ============ Remote Client Controller ============

// RemoteClientController implements client.ClientController via HTTP calls.
type RemoteClientController struct {
	client *di.ProxyClient
}

// NewRemoteClientController creates a remote client controller.
//
//	remote := sdk.NewRemoteClientController("http://sso:8080")
//	client.ClientGateway.Override(remote)
func NewRemoteClientController(baseURL string, opts ...di.RemoteOption) *RemoteClientController {
	return &RemoteClientController{
		client: di.NewProxyClient(baseURL, clientApi.ClientRoutes, opts...),
	}
}

func (r *RemoteClientController) ClientCreate(ctx context.Context, req *clientV1.ClientCreateRequest) (*clientV1.ClientResponse, error) {
	return di.Call[clientV1.ClientResponse](r.client, ctx, "ClientCreate", req)
}

func (r *RemoteClientController) ClientDelete(ctx context.Context, req *clientV1.ClientDeleteRequest) error {
	return di.CallVoid(r.client, ctx, "ClientDelete", req)
}

func (r *RemoteClientController) ClientList(ctx context.Context, req *clientV1.ClientListRequest) (*clientV1.ClientListResponse, error) {
	return di.Call[clientV1.ClientListResponse](r.client, ctx, "ClientList", req)
}

func (r *RemoteClientController) ClientUpdate(ctx context.Context, req *clientV1.ClientUpdateRequest) (*clientV1.ClientResponse, error) {
	return di.Call[clientV1.ClientResponse](r.client, ctx, "ClientUpdate", req)
}
