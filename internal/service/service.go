package service

import (
	"context"
	"strconv"

	"github.com/AkulinIvan/grpc/internal/repo"
	"github.com/AkulinIvan/grpc/pkg/jwt"
	"github.com/AkulinIvan/grpc/pkg/secure"
	"github.com/AkulinIvan/grpc/pkg/validator"

	ssov1 "github.com/AkulinIvan/grpc/proto"
	"github.com/pkg/errors"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)




type GRPCServer struct {
	repo repo.Repository
	log  *zap.SugaredLogger
	ssov1.UnimplementedAuthServiceServer
}

func NewAuthServer(repo repo.Repository, log *zap.SugaredLogger) ssov1.AuthServiceServer {
	return &GRPCServer{
		repo: repo,
		log:  log,
	}
}

func (s *GRPCServer) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validator.Validate(ctx, req); err != nil {
		s.log.Errorf("validation error: %v", err)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	passwordValidityCheck, err := secure.IsValidPassword(req.Password)

	if !passwordValidityCheck {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	req.Password, _ = secure.HashPassword(req.Password)

	_, err = s.repo.CreateUser(ctx, &repo.User{
		Username:       req.GetUsername(),
		HashedPassword: req.GetPassword(),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create user")
	}

	return &ssov1.RegisterResponse{}, nil
}

func (s *GRPCServer) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	// Валидируем входные данные.
	if err := validator.Validate(ctx, req); err != nil {
		s.log.Errorf("validation error: %v", err)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Получаем хэшированный пароль и user из репозитория по username.
	user, err := s.repo.GetUserByUsername(ctx, req.GetUsername())
	if err != nil {
		s.log.Errorf("failed to get credentials for user %s: %v", req.GetUsername(), err)
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Сравниваем хэшированный пароль с введённым.
	if err := secure.CheckPassword(user.HashedPassword, req.GetPassword()); err != nil {
		s.log.Errorf("invalid password for user %s: %v", req.GetUsername(), err)
		return nil, status.Error(codes.Unauthenticated, "invalid username or password")
	}

	// Генерируем access и refresh токены.
	accessToken, err := jwt.GenerateAccessToken(strconv.FormatInt(user.ID, 10))
	if err != nil {
		s.log.Errorf("failed to generate access token for user %s: %v", req.GetUsername(), err)
		return nil, errors.Wrap(err, "failed to generate token")
	}
	refreshToken, err := jwt.GenerateRefreshToken(strconv.FormatInt(user.ID, 10))
	if err != nil {
		s.log.Errorf("failed to generate refresh token for user %s: %v", req.GetUsername(), err)
		return nil, errors.Wrap(err, "failed to generate token")
	}

	return &ssov1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
