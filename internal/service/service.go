package service

import (
	"context"
	"strconv"
	"time"

	"github.com/AkulinIvan/grpc/internal/config"
	"github.com/AkulinIvan/grpc/internal/repo"
	"github.com/AkulinIvan/grpc/pkg/jwt"
	"github.com/AkulinIvan/grpc/pkg/secure"
	"github.com/AkulinIvan/grpc/pkg/validator"
	AuthService "github.com/AkulinIvan/grpc/proto"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authServer struct {
	cfg                   config.AppConfig
	repo                  repo.Repository
	log                   *zap.SugaredLogger
	jwt                   jwt.JWTClient
	numberPasswordEntries *cache.Cache
	AuthService.UnimplementedAuthServiceServer
}

func NewAuthServer(cfg config.AppConfig, repo repo.Repository, jwt jwt.JWTClient, log *zap.SugaredLogger) AuthService.AuthServiceServer {
	return &authServer{
		cfg:  cfg,
		repo: repo,
		log:  log,
		jwt:  jwt,
		numberPasswordEntries: cache.New(
			cfg.System.LockPasswordEntry,
			cfg.System.LockPasswordEntry,
		),
	}
}

func (a *authServer) Register(ctx context.Context, req *AuthService.RegisterRequest) (*AuthService.RegisterResponse, error) {
	if err := validator.Validate(ctx, req); err != nil {
		a.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	passwordValidityCheck, err := secure.IsValidPassword(req.Password)

	if !passwordValidityCheck {

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	req.Password, _ = secure.HashPassword(req.Password)

	_, err = a.repo.GetUserByUsername(ctx, req.Username)
	if err == nil {
		a.log.Error("Creating a new user failed: this user is exist", zap.Error(err))
		return &AuthService.RegisterResponse{Message: "User is exist"}, errors.Wrap(err, "user is exist")
	}

	_, err = a.repo.CreateUser(ctx, &repo.User{
		Username:       req.GetUsername(),
		HashedPassword: req.GetPassword(),
	})

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return nil, status.Error(codes.AlreadyExists, ErrUserAuthAlreadyExist)
			}
		}

		return nil, errors.Wrap(err, "failed to create user")
	}

	return &AuthService.RegisterResponse{}, nil
}

func (a *authServer) Login(ctx context.Context, req *AuthService.LoginRequest) (*AuthService.LoginResponse, error) {
	if err := validator.Validate(ctx, req); err != nil {
		a.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	user, err := a.repo.GetUserByUsername(ctx, req.GetUsername())
	if err != nil {
		a.log.Errorf("failed to get credentials for user %a: %v", req.GetUsername(), err)

		return nil, status.Error(codes.NotFound, "user not found")
	}

	if err := secure.CheckPassword(user.HashedPassword, req.GetPassword()); err != nil {
		a.log.Errorf("invalid password for user %a: %v", req.GetUsername(), err)

		return nil, status.Error(codes.Unauthenticated, "invalid username or password")
	}

	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: user.ID,
	})

	if err != nil {
		a.log.Errorf("failed to generate access token for user %a: %v", req.GetUsername(), err)

		return nil, errors.Wrap(err, "failed to generate token")
	}

	return &AuthService.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *authServer) UpdatePassword(ctx context.Context, req *AuthService.UpdatePasswordRequest) (*AuthService.UpdatePasswordResponse, error) {

	remainingAttempts, err := a.checkRemainingAttempts(req.UserId)
	if err != nil {
		return nil, err
	}

	passwordValidityCheck, err := secure.IsValidPassword(req.NewPassword)

	if !passwordValidityCheck {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	password, err := a.repo.GetPassword(ctx, req.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {

			return nil, status.Error(codes.NotFound, ErrUserNotFound)
		}

		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	err = secure.CheckPassword(password, req.Password)

	if req.Password != "" && err != nil {
		a.numberPasswordEntries.Set(strconv.FormatInt(req.UserId, 10), remainingAttempts-1, cache.DefaultExpiration)

		return nil, status.Errorf(
			codes.InvalidArgument,
			"%s %d",
			ErrValidatePassword,
			remainingAttempts-1,
		)
	}

	err = secure.CheckPassword(password, req.NewPassword)
	if err == nil {
		return nil, status.Error(codes.InvalidArgument, ErrPasswordMatchOldPassword)
	}

	req.NewPassword, err = secure.HashPassword(req.NewPassword)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}

	err = a.repo.UpdatePassword(ctx, req.UserId, req.NewPassword)
	if err != nil {

		return nil, status.Errorf(codes.Internal, ErrUnknown)
	}

	a.numberPasswordEntries.Delete(strconv.FormatInt(req.UserId, 10))

	return &AuthService.UpdatePasswordResponse{Message: "The password change was successful"}, nil
}

func (a *authServer) checkRemainingAttempts(userId int64) (int64, error) {

	remainingAttempts := a.cfg.System.NumberPasswordAttempts
	remainingAttemptsFromCache, expirationTime, ok := a.numberPasswordEntries.GetWithExpiration(strconv.FormatInt(userId, 10))

	if ok && remainingAttemptsFromCache.(int64) == 0 {
		return 0, lockForActionErr(expirationTime)
	}
	if ok {
		remainingAttempts = remainingAttemptsFromCache.(int64)
	}
	return remainingAttempts, nil

}

func (a *authServer) Validate(ctx context.Context, req *AuthService.ValidateRequest) (*AuthService.ValidateResponse, error) {

	_, err := a.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	accessData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	_, err = a.repo.GetRefreshToken(ctx, accessData.UserId)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
		}

		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.ValidateResponse{
		UserId: accessData.UserId,
	}, nil
}

func (a *authServer) NewJwt(ctx context.Context, req *AuthService.NewJwtRequest) (*AuthService.NewJwtResponse, error) {

	if err := validator.Validate(ctx, req); err != nil {
		a.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: req.UserId,
	})

	if err != nil {
		a.log.Errorf("create tokens err: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	if tokens == nil {
		return nil, status.Error(codes.Internal, "failed to generate tokens")
	}

	expiresAt := time.Now().Add(24 * time.Hour * 7) // 7 days
	err = a.repo.NewRefreshToken(ctx, req.UserId, tokens.RefreshToken, expiresAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgerrcode.ForeignKeyViolation:
				return nil, status.Error(codes.NotFound, ErrUserNotFound)
			case pgerrcode.UniqueViolation:
				return nil, status.Error(codes.AlreadyExists, "token already exists")
			}
		}
		a.log.Errorf("database error: %v", err)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.NewJwtResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *authServer) RevokeJwt(ctx context.Context, req *AuthService.RevokeJwtRequest) (*AuthService.RevokeJwtResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}

	err := a.repo.DeleteRefreshToken(ctx, req.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "no tokens found for user")
		}
		a.log.Errorf("failed to revoke tokens for user %d: %v", req.UserId, err)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.RevokeJwtResponse{}, nil
}

func (a *authServer) Refresh(ctx context.Context, req *AuthService.RefreshRequest) (*AuthService.RefreshResponse, error) {
	// Проверяем refresh token
	refreshData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil || refreshData == nil {
		a.log.Errorf("invalid refresh token: %v", err)
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	// Проверяем access token (опционально, если нужно)
	accessData, _ := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})
	if accessData != nil && accessData.UserId != refreshData.UserId {
		return nil, status.Error(codes.Unauthenticated, "token mismatch")
	}

	// Проверяем существование токена в БД
	storedToken, err := a.repo.GetRefreshToken(ctx, refreshData.UserId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, ErrTokenNotFound)
		}
		a.log.Errorf("failed to get refresh token: %v", err)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	if storedToken != req.RefreshToken {
		a.log.Errorf("token mismatch: stored vs provided")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	// Генерируем новые токены
	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: refreshData.UserId,
	})
	if err != nil || tokens == nil {
		a.log.Errorf("failed to create tokens: %v", err)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	// Обновляем токен в БД
	expiresAt := time.Now().Add(a.cfg.GRPC.RefreshTokenTTL)
	err = a.repo.UpdateRefreshToken(ctx, refreshData.UserId, req.RefreshToken, tokens.RefreshToken, expiresAt)
	if err != nil {
		a.log.Errorf("failed to update refresh token: %v", err)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.RefreshResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
