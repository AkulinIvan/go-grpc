package api

import (
	"github.com/AkulinIvan/grpc/internal/service"

	"google.golang.org/grpc"
)

type Server struct {
	Service service.AuthService
}

func New(s *Server) *grpc.Server {
	gPRCServer := grpc.NewServer()

	service.RegisterUser(gPRCServer)

	return gPRCServer
}