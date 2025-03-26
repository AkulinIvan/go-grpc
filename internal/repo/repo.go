package repo

import (
	"context"
	"fmt"

	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

const (
	createUserQuery = `
		INSERT INTO users (username, hashed_password, email, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id;
	`

	getUserByUsernameQuery = `
		SELECT id, username, hashed_password, email, created_at, updated_at
		FROM users
		WHERE username = $1;
	`
)

// Repository определяет интерфейс для работы с данными пользователей.
type Repository interface {
	// CreateUser создает пользователя и возвращает его ID.
	CreateUser(ctx context.Context, user *User) (int, error)
	// GetUserCredentials возвращает данные пользователя (включая хэшированный пароль) по username.
	GetUserByUsername(ctx context.Context, username string) (*User, error)
}

type repository struct {
	pool *pgxpool.Pool
}

func NewRepository(ctx context.Context, cfg config.PostgreSQL) (Repository, error) {
	// Формируем строку подключения
	connString := fmt.Sprintf(
		`user=%s password=%s host=%s port=%d dbname=%s sslmode=%s 
        pool_max_conns=%d pool_max_conn_lifetime=%s pool_max_conn_idle_time=%s`,
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
		cfg.SSLMode,
		cfg.PoolMaxConns,
		cfg.PoolMaxConnLifetime.String(),
		cfg.PoolMaxConnIdleTime.String(),
	)

	// Парсим конфигурацию подключения
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse PostgreSQL config")
	}

	// Оптимизация выполнения запросов (кеширование запросов)
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	// Создаём пул соединений с базой данных
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PostgreSQL connection pool")
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, errors.Wrap(err, "the connection doesn't ping")
	}

	return &repository{pool}, nil

}

func (r *repository) CreateUser(ctx context.Context, user *User) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx, createUserQuery, user.Username, user.HashedPassword).Scan(&id)

	if err != nil {
		return 0, errors.Wrap(err, "Error, user already exists")
	}
	return id, nil
}

func (r *repository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := r.pool.QueryRow(ctx, getUserByUsernameQuery, username).Scan(
		&user.ID,
		&user.Username,
		&user.HashedPassword,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user credentials")
	}
	return &user, nil
}
