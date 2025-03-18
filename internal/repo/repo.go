package repo

import "context"

type repository struct {
	users map[string]User
}

type Repository interface {
	Register(ctx context.Context) error
	Login(ctx context.Context) error
}

func NewRepository(ctx context.Context) (Repository, error) {
	var users = make(map[string]User)

	return &repository{users: users}, nil
}


func (r *repository) Register(ctx context.Context) error {
	// здесь будет метод регистрации пользователя
	return nil
}

func (r *repository) Login(ctx context.Context) error {
	// здесь будет метод авторизации пользователя
	return nil
}