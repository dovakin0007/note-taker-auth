package server

import (
	"Auth/internal/services"
	"Auth/internal/utils"
	"fmt"
	"net/http"
	"net/mail"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/time/rate"
)

var limiters = make(map[string]*rate.Limiter)

func (s *Server) RegisterRoutes() http.Handler {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Add your frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true, // Enable cookies/auth
	}))

	{
		authRoute := r.Group("/auth")
		authRoute.POST("/register", s.Register)

		authRoute.POST("/login", s.AuthenticateUser)
		authRoute.GET("/oauth/login", s.OauthLogin)
		authRoute.GET("/google/callback", s.OauthCallback)
		authRoute.POST("/logout", s.Logout)
		authRoute.POST("/refresh", s.RefreshToken)
	}

	return r
}

func (s *Server) Register(c *gin.Context) {
	ip := c.ClientIP()
	var input struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
		Email    string `json:"email" validate:"required,email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	err := validator.New().Struct(input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed"})
		return
	}
	if _, exists := limiters[ip]; !exists {
		limiters[ip] = rate.NewLimiter(1, 5)
	}
	limiter := limiters[ip]
	if !limiter.Allow() {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
		return
	}
	v, err := mail.ParseAddress(input.Email) // Validate email format
	_ = v
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}
	user, err := services.RegisterUser(s.db, input.Username, input.Email, input.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully", "user": user})
	delete(limiters, ip)
}

func (s *Server) AuthenticateUser(c *gin.Context) {
	var input struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}
	ip := c.ClientIP()
	if _, exists := limiters[ip]; !exists {
		limiters[ip] = rate.NewLimiter(1, 5) // 1 request per second with a burst capacity of 5
	}
	limiter := limiters[ip]
	if !limiter.Allow() {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too Many Requests"})
		c.Abort()
		return
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	err := validator.New().Struct(input)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed"})
		return
	}

	user, err := services.AuthenticateUser(s.db, input.Email, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}
	fmt.Println("Authenticated user:", user)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	appToken, err := utils.GenerateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT access token creation failed"})
		return
	}
	refreshToken, err := utils.GenerateRefreshToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT refresh token creation failed"})
		return
	}
	c.SetSameSite(http.SameSiteNoneMode)
	c.SetCookie("token", appToken, 3600, "/", "localhost", false, false)
	c.SetCookie("refresh_token", refreshToken, 60*60*24*30, "/", "localhost", false, false)
	delete(limiters, ip)
	c.JSON(http.StatusOK, gin.H{"message": "Authentication successful", "token": appToken, "user": user})

}

func (s *Server) OauthLogin(c *gin.Context) {
	token := services.HandleGoogleOauthLogin(s.authconf, c)
	c.Redirect(http.StatusTemporaryRedirect, token)
}

func (s *Server) OauthCallback(c *gin.Context) {
	user, err := services.HandleGoogleCallback(s.db, s.authconf, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to handle OAuth callback"})
		return
	}
	appToken, err := utils.GenerateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT access token creation failed"})
		return
	}
	refreshToken, err := utils.GenerateRefreshToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT refresh token creation failed"})
		return
	}
	c.SetCookie("token", appToken, 900, "/", "localhost", false, true)
	c.SetCookie("refresh_token", refreshToken, 60*60*24*30, "/", "localhost", true, true)
	c.JSON(http.StatusOK, gin.H{
		"token": appToken,
		"user": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"username": user.Username,
		},
	})

}

func (s *Server) Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// TODO: Test Refresh Token see whether it works as expected
func (s *Server) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token found"})
		return
	}

	userID, err := utils.ValidateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	appToken, err := utils.GenerateJWT(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new access token"})
		return
	}

	c.SetCookie("token", appToken, 3600, "/", "localhost", true, true)
	c.JSON(http.StatusOK, gin.H{"token": appToken})
}
