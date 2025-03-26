package jwt

// Пример генерации access-токена (замените на вашу реализацию)
func GenerateAccessToken(userID string) (string, error) {
	// Здесь может быть JWT генерация.
	return "dummyAccessTokenFor_" + userID, nil
}

// Пример генерации refresh-токена (замените на вашу реализацию)
func GenerateRefreshToken(userID string) (string, error) {
	return "dummyRefreshTokenFor_" + userID, nil
}
