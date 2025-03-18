package config

import "time"

// Общая конфигурация сервиса, тут должны быть все переменные

type AppConfig struct {
	LogLevel string
	GRPC     GRPCConfig
	TokenTTL time.Duration `json:"token_ttl" env-default:"1h"`
}

type GRPCConfig struct {
	Port    string        `envconfig:"PORT" required:"true"`
	Token   string        `envconfig:"TOKEN" required:"true"`
	Timeout time.Duration `json:"timeout"`
}
