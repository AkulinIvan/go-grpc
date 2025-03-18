package main

import (
	"context"
	"fmt"
	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/AkulinIvan/grpc/internal/repo"
	"github.com/AkulinIvan/grpc/internal/service"
	"log"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"

	customLogger "github.com/AkulinIvan/grpc/internal/logger"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Printf(".env file doesn't exist or can't read .env")
	}

	var cfg config.AppConfig
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatal(errors.Wrap(err, "failed to load configuration"))
	}

	logger, err := customLogger.NewLogger(cfg.LogLevel)
	if err != nil {
		log.Fatal(errors.Wrap(err, "error initializing logger"))
	}

	repository, err := repo.NewRepository(context.Background())
	if err != nil {
		log.Fatal(errors.Wrap(err, "failed to initialize repository"))
	}

	serviceInstance := service.NewService(repository, logger)

	fmt.Println(serviceInstance) // изменить заглушку на инициализацию роутера
}