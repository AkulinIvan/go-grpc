package repo

import "time"

type User struct {
	ID             int64     // Идентификатор пользователя
	Username       string    // Имя пользователя (логин)
	HashedPassword string    // Хэшированный пароль
	Email          string    // email
	CreatedAt      time.Time // Время создания
	UpdatedAt      time.Time // Время последнего обновления
}
