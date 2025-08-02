package services

import (
	"Auth/internal/database"
	"Auth/internal/models"
	"Auth/internal/utils"
	"context"
	"encoding/json"

	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func RegisterUser(db database.Service, username, email, password string) (*models.User, error) {
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Username: username,
		Email:    email,
		Password: hashedPassword,
	}

	return &user, db.CreateUser(&user)
}

func AuthenticateUser(db database.Service, email, password string) (*models.User, error) {
	var user models.User

	if _, err := db.GetFirstUserByEmail(email); err != nil {
		return nil, err
	}

	if !utils.CheckPasswordHash(password, user.Password) {
		return nil, nil
	}
	return &user, nil
}

func HandleGoogleOauthLogin(conf *oauth2.Config, token string) string {
	_ = token // This is just a placeholder to show where the token would be used.
	// Handle the exchange code to initiate a transport.
	tok := conf.AuthCodeURL("random-state-string", oauth2.AccessTypeOffline)
	return tok
}

func HandleGoogleCallback(db database.Service, conf *oauth2.Config, code string) (*models.User, error) {
	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}
	client := conf.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	var userInfo struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
		Id      string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	result, err := db.GetFirstUserByEmail(userInfo.Email)

	if err == gorm.ErrRecordNotFound {
		db.CreateUser(&models.User{
			Username: userInfo.Name,
			Email:    userInfo.Email,
			Password: "", // Password is not used for OAuth users
		})
		result = &models.User{
			Username: userInfo.Name,
			Email:    userInfo.Email,
			Password: "", // Password is not used for OAuth users
		}
	} else if (err != nil && err != gorm.ErrRecordNotFound) || result == nil {
		return nil, err
	}
	return result, nil

}
