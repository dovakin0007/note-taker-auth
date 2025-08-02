package server

import (
	"Auth/internal/services"
	"Auth/internal/utils"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
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

	r.GET("/", s.HelloWorldHandler)

	r.GET("/health", s.healthHandler)

	{
		authRoute := r.Group("/auth")
		authRoute.POST("/register", s.Register)

		authRoute.POST("/login", s.AuthenticateUser)
		authRoute.POST("/oauth/login", s.OauthLogin)
		authRoute.GET("/google/callback", s.OauthCallback)
	}

	return r
}

func (s *Server) HelloWorldHandler(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Hello World"

	c.JSON(http.StatusOK, resp)
}

func (s *Server) Register(c *gin.Context) {
	ip := c.ClientIP()
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
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
	user, err := services.RegisterUser(s.db, input.Username, input.Password, input.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully", "user": user})

}

func (s *Server) AuthenticateUser(c *gin.Context) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	user, err := services.AuthenticateUser(s.db, input.Email, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	appToken, err := utils.GenerateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT creation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Authentication successful", "token": appToken, "user": user})
}

func (s *Server) OauthLogin(c *gin.Context) {
	token := services.HandleGoogleOauthLogin(s.authconf, c.Query("token"))
	println("Redirecting to Google OAuth URL:", token)
	c.Redirect(http.StatusTemporaryRedirect, token)
}

func (s *Server) OauthCallback(c *gin.Context) {
	user, err := services.HandleGoogleCallback(s.db, s.authconf, c.Query("code"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to handle OAuth callback"})
		return
	}
	appToken, err := utils.GenerateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT creation failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token": appToken,
		"user": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"username": user.Username,
		},
	})

}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.db.Health())
}
