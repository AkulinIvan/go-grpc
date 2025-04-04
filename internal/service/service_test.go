package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/AkulinIvan/grpc/internal/repo"
	"github.com/AkulinIvan/grpc/internal/repo/mocks"
	AuthService "github.com/AkulinIvan/grpc/proto"
)

type authServerDependencies struct {
	repo *mocks.Repository
}

func setupAuthServer(*testing.T) (*authServer, *authServerDependencies) {
	cfg := config.AppConfig{
		System: config.System{
			LockPasswordEntry: 5,
		},
	}

	deps := &authServerDependencies{
		repo: &mocks.Repository{},
	}

	server := &authServer{
		cfg:                   cfg,
		repo:                  deps.repo,
		numberPasswordEntries: cache.New(cfg.System.LockPasswordEntry, cfg.System.LockPasswordEntry),
	}

	return server, deps
}

func TestRegister(t *testing.T) {
	t.Run("регистрация прошла успешно", func(t *testing.T) {
		server, deps := setupAuthServer(t)

		req := &AuthService.RegisterRequest{
			Username: "testuser",
			Password: "ValidPass123!",
		}

		deps.repo.On("GetUserByUsername", mock.Anything, req.Username).
			Return(nil, errors.New("user not found")).
			Once()

		deps.repo.On("CreateUser", mock.Anything, mock.MatchedBy(func(user *repo.User) bool {
			return user.Username == req.Username && user.HashedPassword != ""
		})).
			Return(&repo.User{Username: req.Username}, nil).
			Once()

		resp, err := server.Register(context.Background(), req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		deps.repo.AssertExpectations(t)
	})

	t.Run("user already exists", func(t *testing.T) {
		server, deps := setupAuthServer(t)

		req := &AuthService.RegisterRequest{
			Username: "existinguser",
			Password: "ValidPass123!",
		}

		deps.repo.On("GetUserByUsername", mock.Anything, req.Username).
			Return(&repo.User{Username: req.Username}, nil).
			Once()

		resp, err := server.Register(context.Background(), req)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user is exist")
		assert.Equal(t, "User is exist", resp.Message)
		deps.repo.AssertExpectations(t)
	})

	t.Run("invalid password", func(t *testing.T) {
		server, _ := setupAuthServer(t)

		req := &AuthService.RegisterRequest{
			Username: "testuser",
			Password: "short",
		}

		resp, err := server.Register(context.Background(), req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("database unique violation", func(t *testing.T) {
		server, deps := setupAuthServer(t)

		req := &AuthService.RegisterRequest{
			Username: "testuser",
			Password: "ValidPass123!",
		}

		pgErr := &pgconn.PgError{
			Code: "23505", // UniqueViolation
		}

		deps.repo.On("GetUserByUsername", mock.Anything, req.Username).
			Return(nil, errors.New("user not found")).
			Once()

		deps.repo.On("CreateUser", mock.Anything, mock.Anything).
			Return(nil, pgErr).
			Once()

		resp, err := server.Register(context.Background(), req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.AlreadyExists, status.Code(err))
		deps.repo.AssertExpectations(t)
	})

	t.Run("database error on create", func(t *testing.T) {
		server, deps := setupAuthServer(t)

		req := &AuthService.RegisterRequest{
			Username: "testuser",
			Password: "ValidPass123!",
		}

		deps.repo.On("GetUserByUsername", mock.Anything, req.Username).
			Return(nil, errors.New("user not found")).
			Once()

		deps.repo.On("CreateUser", mock.Anything, mock.Anything).
			Return(nil, errors.New("db error")).
			Once()

		resp, err := server.Register(context.Background(), req)

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Contains(t, err.Error(), "failed to create user")
		deps.repo.AssertExpectations(t)
	})
}
