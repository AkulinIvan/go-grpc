package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/AkulinIvan/grpc/internal/repo"
	"github.com/AkulinIvan/grpc/internal/service"
	"google.golang.org/grpc"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"

	customLogger "github.com/AkulinIvan/grpc/pkg/logger"

	// Сгенерированный код
	"github.com/AkulinIvan/grpc/proto"
)

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		log.Printf(".env file doesn't exist or can't read .env")
	}

	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	logger, err := customLogger.NewLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf("error initializing logger: %v", err)
	}
	defer logger.Sync()
	ctx := context.Background()
	repository, err := repo.NewRepository(ctx, cfg.PostgreSQL)
	if err != nil {
		log.Fatalf("failed to initialize repository: %v", err)
	}

	// Создаем сервис авторизации.
	authSrv := service.NewAuthServer(repository, logger)

	// Создаем gRPC-сервер.
	grpcServer := grpc.NewServer()
	ssov1.RegisterAuthServiceServer(grpcServer, authSrv)

	// Слушаем адрес, указанный в конфигурации.
	lis, err := net.Listen("tcp", cfg.GRPC.ListenAddress)
	if err != nil {
		logger.Fatalf("failed to listen on %s: %v", cfg.GRPC.ListenAddress, err)
	}

	// Запускаем сервер в горутине.
	go func() {
		logger.Infof("gRPC server started on %s", cfg.GRPC.ListenAddress)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatalf("failed to serve: %v", err)
		}
	}()

	// Обработка сигналов для корректного завершения работы сервера.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down gRPC server...")
	grpcServer.GracefulStop()
}
