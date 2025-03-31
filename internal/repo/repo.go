package repo

import (
	"context"
	"fmt"
	"time"

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
	getPasswordQuery = `
		SELECT password_hash
		FROM users
		WHERE id = @userID
	`
	updatePasswordQuery = `
		UPDATE users 
		SET password_hash = @newPassword, 
		    updated_at = NOW() 
		WHERE id = @userID
	`
	getRefreshTokenQuery = `
		SELECT token, expires_at
		FROM refresh_tokens
		WHERE user_id = @userID
		AND revoked = false
		AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`
	deleteRefreshTokenQuery = `
		UPDATE refresh_tokens
		SET revoked = true,	revoked_at = NOW()
		WHERE token = @token
		AND revoked = false
	`
	newRefreshTokenQuery = `
		INSERT INTO refresh_tokens 
		(user_id, token, expires_at, created_at, revoked) 
		VALUES 
		(@userID, @token, @expiresAt, @createdAt, false)
	`
	//update token
	checkQuery = `
		SELECT token 
		FROM refresh_tokens
		WHERE token = @oldToken
		AND user_id = @userID
		AND revoked = false
		AND expires_at > NOW()
		FOR UPDATE
	`
	revokeQuery = `
		UPDATE refresh_tokens
		SET revoked = true,
			revoked_at = NOW(),
			replaced_by = @newToken
		WHERE token = @oldToken
	`
	insertQuery = `
		INSERT INTO refresh_tokens
			(user_id, token, expires_at, created_at, revoked)
		VALUES
			(@userID, @newToken, @newExpiresAt, NOW(), false)
	`
)

// Repository определяет интерфейс для работы с данными пользователей.
type Repository interface {
	// CreateUser создает пользователя и возвращает его ID.
	CreateUser(ctx context.Context, user *User) (int, error)
	// GetUserCredentials возвращает данные пользователя (включая хэшированный пароль) по username.
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	GetPassword(ctx context.Context, userID int64) (string, error)
	UpdatePassword(context.Context, int64, string) error

	DeleteRefreshToken(ctx context.Context, userID int64) error
	GetRefreshToken(ctx context.Context, userID int64) (string, error)
	NewRefreshToken(ctx context.Context, userID int64, token string, expiresAt time.Time) error
	UpdateRefreshToken(ctx context.Context, userID int64, oldToken string, newToken string, newExpiresAt time.Time) error
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

// Функция для сохранения хешированного пароля в базу данных
func (r *repository) GetPassword(ctx context.Context, userID int64) (string, error) {
	args := pgx.NamedArgs{
		"userID": userID,
	}

	var passwordHash string
	err := r.pool.QueryRow(ctx, getPasswordQuery, args).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("user with ID %d not found", userID)
		}
		return "", fmt.Errorf("failed to get password: %w", err)
	}

	return passwordHash, nil
}

func (r *repository) UpdatePassword(ctx context.Context, userID int64, newPassword string) error {
	if newPassword == "" {
		return errors.New("new password hash can't be empty")
	}
	args := pgx.NamedArgs{
		"userID":      userID,
		"newPassword": newPassword,
	}
	// Выполняем запрос
	cmdTag, err := r.pool.Exec(ctx, updatePasswordQuery, args)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Проверяем, что была обновлена exactly одна запись
	if cmdTag.RowsAffected() != 1 {
		return fmt.Errorf("expected to update 1 row, but updated %d", cmdTag.RowsAffected())
	}

	return nil
}

func (r *repository) GetRefreshToken(ctx context.Context, userID int64) (string, error) {
	args := pgx.NamedArgs{
		"userID": userID,
	}

	var token string

	err := r.pool.QueryRow(ctx, getRefreshTokenQuery, args).Scan(&token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("no valid refresh token found for user %d", userID)
		}
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}

	return token, nil
}

func (r *repository) NewRefreshToken(ctx context.Context, userID int64, token string, expiresAt time.Time) error {
	args := pgx.NamedArgs{
		"userID":    userID,
		"token":     token,
		"expiresAt": expiresAt,
		"createdAt": time.Now().UTC(),
	}

	_, err := r.pool.Exec(ctx, newRefreshTokenQuery, args)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	return nil
}

// Функция для удаления refresh-токена
func (r *repository) DeleteRefreshToken(ctx context.Context, userID int64) error {
	args := pgx.NamedArgs{
		"userID": userID,
	}

	cmdTag, err := r.pool.Exec(ctx, deleteRefreshTokenQuery, args)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("refresh token not found or already revoked")
	}

	return nil
}

func (r *repository) UpdateRefreshToken(ctx context.Context, userID int64, oldToken string, newToken string, newExpiresAt time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Проверяем существование и валидность старого токена
	var existingToken string

	err = tx.QueryRow(ctx, checkQuery, pgx.NamedArgs{
		"oldToken": oldToken,
		"userID":   userID,
	}).Scan(&existingToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("invalid or expired refresh token")
		}
		return fmt.Errorf("failed to validate refresh token: %w", err)
	}

	// 2. Помечаем старый токен как отозванный

	_, err = tx.Exec(ctx, revokeQuery, pgx.NamedArgs{
		"oldToken": oldToken,
		"newToken": newToken,
	})
	if err != nil {
		return fmt.Errorf("failed to revoke old token: %w", err)
	}

	// 3. Создаем новый токен

	_, err = tx.Exec(ctx, insertQuery, pgx.NamedArgs{
		"userID":       userID,
		"newToken":     newToken,
		"newExpiresAt": newExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("failed to create new token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
