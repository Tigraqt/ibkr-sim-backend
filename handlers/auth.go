package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Tigraqt/ibkr-sim-backend/config"
	"github.com/Tigraqt/ibkr-sim-backend/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func Register(w http.ResponseWriter, r *http.Request) error {
	var creds RegisterFields

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		return InvalidJSON()
	}

	defer r.Body.Close()

	if errors := creds.validate(); len(errors) > 0 {
		return InvalidRequestData(errors)
	}

	// Check if username or email already exists
	var existingUser models.User
	if result := config.DB.Where("username = ? OR email = ?", creds.Username, creds.Email).First(&existingUser); result.Error == nil {
		if existingUser.Username == creds.Username {
			return NewAPIError(http.StatusConflict, fmt.Errorf("username already exists"))
		} else if existingUser.Email == creds.Email {
			return NewAPIError(http.StatusConflict, fmt.Errorf("email already exists"))
		}
	} else if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return fmt.Errorf("database error: %w", result.Error)
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)

	if err != nil {
		return NewAPIError(http.StatusInternalServerError, fmt.Errorf("error creating user"))
	}

	user := models.User{
		ID:                uuid.New(),
		Username:          creds.Username,
		Password:          string(hashPassword),
		Email:             creds.Email,
		FullName:          creds.FullName,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		Balance:           0,
		ProfilePictureURL: "",
		Role:              "user",
	}

	if result := config.DB.Create(&user); result.Error != nil {
		return NewAPIError(http.StatusInternalServerError, fmt.Errorf("error saving user to database"))
	}

	return writeJSON(w, http.StatusCreated, user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var creds LoginCredentials

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	// Validate the fields
	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	var user models.User
	if result := config.DB.Where("username = ?", creds.Username).First(&user); result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error retrieving user", http.StatusInternalServerError)
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().UTC().Add(time.Hour * 24)
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    string("ibkr-sim-backend"),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Subject:   fmt.Sprintf("%d", user.ID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secret := os.Getenv("JWT_SECRET")

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"token":   tokenString,
	})
}
