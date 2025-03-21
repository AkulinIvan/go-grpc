package service

import (
	"context"

	"github.com/AkulinIvan/grpc/internal/repo"
	ssov1 "github.com/AkulinIvan/grpc/proto"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type AuthService interface {
	Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error)
	Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error)
}

type GRPCServer struct {
	repo repo.Repository
	log  *zap.SugaredLogger
	ssov1.UnimplementedAuthServiceServer
}


func NewProtoService(repo repo.Repository, logger *zap.SugaredLogger) *GRPCServer {
	return &GRPCServer{
		repo:                           repo,
		log:                            logger,
		UnimplementedAuthServiceServer: ssov1.UnimplementedAuthServiceServer{},
	}
}


func RegisterUser(grpc *grpc.Server) {
	ssov1.RegisterAuthServiceServer(grpc, &GRPCServer{})
}

func (s *GRPCServer) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	credentials := &repo.User{
		Login:    req.Username,
		Password: req.Password,
	}
	err := s.repo.Register(ctx, *credentials)
	if err != nil {
		return nil, err
	}
	var response = ssov1.RegisterResponse{
		Message: "Registered successfully", // TODO should be a constant??
	}
	return &response, nil
}

func (s *GRPCServer) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	credentials := &repo.User{
		Login:    req.Username,
		Password: req.Password,
	}
	token, err := s.repo.Login(ctx, *credentials)
	if err != nil {
		return nil, err // TODO
	}
	response := ssov1.LoginResponse{
		Token: token,
	}
	return &response, nil // TODO Register Login
}
