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
	"github.com/pkg/errors"

	customLogger "github.com/AkulinIvan/grpc/internal/logger"

	// Сгенерированный код
	ssov1 "github.com/AkulinIvan/grpc/proto"
)

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		log.Printf(".env file doesn't exist or can't read .env")
	}

	var cfg config.Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatal(errors.Wrap(err, "failed to load configuration"))
	}

	logger, err := customLogger.NewLogger(cfg.LogLevel)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error initializing logger"))
	}

	repository, err := repo.NewRepository(context.Background(), cfg.PostgreSQL)
	if err != nil {
		log.Fatal(errors.Wrap(err, "failed to initialize repository"))
	}

	listener, _ := net.Listen("tcp", ":50051")

	grpcInstance := grpc.NewServer()

	ssov1.RegisterAuthServiceServer(grpcInstance, service.NewProtoService(repository, logger))

	go func() {
		logger.Infof("Starting gRPC server on port 50051")
		if err := grpcInstance.Serve(listener); err != nil {
			log.Fatal(errors.Wrap(err, "failed to start server"))
		}

	}()

	// Ожидание системных сигналов для корректного завершения работы
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan

	logger.Info("Shutting down gracefully...")

}
