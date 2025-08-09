package services

import (
	"Auth/internal/database"
	"Auth/internal/models"
	"Auth/internal/utils"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func RegisterUser(db database.Service, username, email, password string) (*models.User, error) {
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}
	log.Printf("Registering user: %s with email: %s, with password: %s", username, email, password)
	user := models.User{
		Username: username,
		Email:    email,
		Password: hashedPassword,
	}

	return &user, db.CreateUser(&user)
}

func AuthenticateUser(db database.Service, email, password string) (*models.User, error) {
	val, err := db.GetFirstUserByEmail(email)
	if err != nil {
		return nil, err
	}

	if !utils.CheckPasswordHash(password, val.Password) {
		return nil, nil
	}
	return val, nil
}

func HandleGoogleOauthLogin(conf *oauth2.Config, c *gin.Context) string {
	state := generateStateOauthCookie(c)
	tok := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return tok
}

func generateStateOauthCookie(c *gin.Context) string {
	var expiration = (time.Now().Add(30 * time.Minute)).Second()
	b := make([]byte, 16)

	rand.Read(b)

	state := base64.URLEncoding.EncodeToString(b)
	c.SetCookie("oauthstate", state, int(expiration), "/", "localhost", false, true)

	return state
}

func HandleGoogleCallback(db database.Service, conf *oauth2.Config, c *gin.Context) (*models.User, error) {
	oauthState, _ := c.Cookie("oauthstate")
	if c.Request.FormValue("state") != oauthState {
		log.Println("invalid oauth google state")
		c.Redirect(http.StatusTemporaryRedirect, "/")
	}

	data, err := getUserDataFromGoogle(db, conf, c, c.Request.FormValue("code"))
	if err != nil {
		log.Println("Error getting user data from Google:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user data from Google"})
		return nil, err
	}
	return data, nil

}

func getUserDataFromGoogle(db database.Service, conf *oauth2.Config, c *gin.Context, code string) (*models.User, error) {
	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
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
