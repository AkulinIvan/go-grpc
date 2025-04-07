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
	UserID          int64  
	Password        string 
	NewPassword     string 
	ConfirmPassword string 
}

type GetRefreshTokenParams struct {
	UserID string 
}

type NewRefreshTokenParams struct {
	UserID       int64
	Token        string
	IPAddress    string
	UserAgent    string
	ExpiresAt    time.Time
	Scope        string
	IsRememberMe bool
}

type DeleteRefreshTokenParams struct {
	Token    string
	UserID   int64
	ClientID string
	Reason   string
}

type UpdateRefreshTokenParams struct {
	GrantType    string
	Token        string
	UserID       string
	ClientSecret string
	CreatedDate  time.Time
	Scope        string
	DeviceID     string
}
