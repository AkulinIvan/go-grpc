package service

import (
	"context"
	"reflect"
	"testing"

	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/AkulinIvan/grpc/internal/repo"
	"github.com/AkulinIvan/grpc/pkg/jwt"
	AuthService "github.com/AkulinIvan/grpc/proto"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

func TestNewAuthServer(t *testing.T) {
	type args struct {
		cfg  config.AppConfig
		repo repo.Repository
		jwt  jwt.JWTClient
		log  *zap.SugaredLogger
	}
	tests := []struct {
		name string
		args args
		want AuthService.AuthServiceServer
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAuthServer(tt.args.cfg, tt.args.repo, tt.args.jwt, tt.args.log); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAuthServer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_Register(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.RegisterRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.RegisterResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.Register(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.Register() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_Login(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.LoginRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.LoginResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.Login(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.Login() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_UpdatePassword(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.UpdatePasswordRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.UpdatePasswordResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.UpdatePassword(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.UpdatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.UpdatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_checkRemainingAttempts(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		userId int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int64
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.checkRemainingAttempts(tt.args.userId)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.checkRemainingAttempts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("authServer.checkRemainingAttempts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_Validate(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.ValidateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.ValidateResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.Validate(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_NewJwt(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.NewJwtRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.NewJwtResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.NewJwt(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.NewJwt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.NewJwt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_RevokeJwt(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.RevokeJwtRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.RevokeJwtResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.RevokeJwt(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.RevokeJwt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.RevokeJwt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authServer_Refresh(t *testing.T) {
	type fields struct {
		cfg                            config.AppConfig
		repo                           repo.Repository
		log                            *zap.SugaredLogger
		jwt                            jwt.JWTClient
		numberPasswordEntries          *cache.Cache
		UnimplementedAuthServiceServer AuthService.UnimplementedAuthServiceServer
	}
	type args struct {
		ctx context.Context
		req *AuthService.RefreshRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AuthService.RefreshResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authServer{
				cfg:                            tt.fields.cfg,
				repo:                           tt.fields.repo,
				log:                            tt.fields.log,
				jwt:                            tt.fields.jwt,
				numberPasswordEntries:          tt.fields.numberPasswordEntries,
				UnimplementedAuthServiceServer: tt.fields.UnimplementedAuthServiceServer,
			}
			got, err := a.Refresh(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("authServer.Refresh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authServer.Refresh() = %v, want %v", got, tt.want)
			}
		})
	}
}
