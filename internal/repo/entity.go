package repo

import "time"

type User struct {
	ID             int64     
	Username       string    
	HashedPassword string    
	CreatedAt      time.Time
	UpdatedAt      time.Time
}	
	

type UpdatePasswordParams struct {
	UserID          int64  `json:"user_id" validate:"required,gt=0"`
	Password        string `json:"current_password" validate:"required,min=8,max=72"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=72,nefield=CurrentPassword"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}

type GetRefreshTokenParams struct {
	UserID       string `json:"client_id" validate:"required,uuid"`
}

type NewRefreshTokenParams struct {
	UserID       int64     `json:"user_id" validate:"required,gt=0"`
	Token        string    `json:"token" validate:"required,max=64"`  // Уникальный идентификатор устройства
	IPAddress    string    `json:"ip_address" validate:"required,ip"` // IP адрес запроса
	UserAgent    string    `json:"user_agent" validate:"required"`    // Информация о клиенте
	ExpiresAt    time.Time `json:"expires_at" validate:"required"`    // Срок действия токена
	Scope        string    `json:"scope" validate:"omitempty"`        // Дополнительные scope
	IsRememberMe bool      `json:"is_remember_me"`                    // Флаг "запомнить меня" (увеличивает срок действия)
}

type DeleteRefreshTokenParams struct {
	Token    string `json:"token" validate:"required,jwt"`       // Сам refresh token
	UserID   int64  `json:"user_id" validate:"required,gt=0"`    // ID пользователя для проверки владельца
	ClientID string `json:"client_id" validate:"omitempty,uuid"` // ID клиентского приложения (опционально)
	Reason   string `json:"reason" validate:"omitempty,max=100"` // Причина удаления (для аудита)
}

type UpdateRefreshTokenParams struct {
	GrantType        string    `json:"grant_type" validate:"required,eq=refresh_token"`
	Token     string    `json:"refresh_token" validate:"required,jwt"`           
	UserID         string    `json:"client_id" validate:"required,uuid"`              
	ClientSecret     string    `json:"client_secret,omitempty"`                        
	CreatedDate time.Time `json:"expires_at,omitempty"`                            
	Scope            string    `json:"scope,omitempty"`                                 
	DeviceID         string    `json:"device_id,omitempty"`                             
}
