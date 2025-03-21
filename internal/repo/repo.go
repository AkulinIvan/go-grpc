package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/dgrijalva/jwt-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

const (
	checkUserQuery  = `SELECT * from userprofile where login = $1` // TODO change later, maybe select true from ...
	insertUserQuery = `INSERT INTO users (id, login, passhash) VALUES (default, $1, $2)`
)


type repository struct {
	pool *pgxpool.Pool
}

type Repository interface {
	Login(ctx context.Context, credentials User) (string, error)
	Register(ctx context.Context, credentials User) (error)
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

func (r *repository) Register(ctx context.Context, user User) error {
	var check bool
	row := r.pool.QueryRow(ctx, checkUserQuery, user.Login).Scan(&check)
	row.Error()
	if check == true {
		return errors.New("Error, user already exists")
	}
	//ctag, err := r.pool.Exec()
	// TODO add to DB
	return nil // TODO add 

}

func (r *repository) Login(ctx context.Context, user User) (string, error) {
	// TODO check if such user exists
	//row := r.pool.QueryRow(ctx, checkUserQuery, credentials.Username)
	// TODO check that row is not empty

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(10 * time.Minute)
	claims["authorized"] = true
	claims["user"] = user.Login
	secret := []byte("secret")
	tokenString, err := token.SignedString(secret) // TODO make this a .env variable, cryptographically random string
	if err != nil {
		return "", err
	}
	// TODO maybe encode tokenString to base64??
	return tokenString, nil

}
