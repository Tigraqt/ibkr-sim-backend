package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
)

type RegisterFields struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type APIError struct {
	StatusCode int `json:"statusCode"`
	Msg        any `json:"msg"`
}

func (e APIError) Error() string {
	return fmt.Sprintf("api error: %d", e.StatusCode)
}

func NewAPIError(statusCode int, err error) APIError {
	return APIError{
		StatusCode: statusCode,
		Msg:        err.Error(),
	}
}

func InvalidRequestData(errors map[string]string) APIError {
	return APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Msg:        errors,
	}
}

func InvalidJSON() APIError {
	return NewAPIError(http.StatusBadRequest, fmt.Errorf("invalid JSON request data"))
}

type APIFunc func(w http.ResponseWriter, r *http.Request) error

func Make(h APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			if apiErr, ok := err.(APIError); ok {
				writeJSON(w, apiErr.StatusCode, apiErr)
			} else {
				errResp := map[string]any{
					"statusCode": http.StatusInternalServerError,
					"msg":        "internal server error",
				}

				writeJSON(w, http.StatusInternalServerError, errResp)
			}

			slog.Error("HTTP API error", "err", err.Error(), "path", r.URL.Path)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func (fields *RegisterFields) validate() map[string]string {
	validationErrors := make(map[string]string)

	if len(fields.Username) < 3 || len(fields.Username) > 20 {
		validationErrors["username"] = "Username must be between 3 and 20 characters"
	}

	usernameRegex := `^[a-zA-Z0-9_-]+$`
	if matched := regexp.MustCompile(usernameRegex).MatchString(fields.Username); !matched {
		validationErrors["username"] = "Username can only contain alphanumeric characters, underscores, and hyphens"
	}

	if len(fields.Password) < 8 {
		validationErrors["password"] = "Password must be at least 8 characters long"
	}

	if !regexp.MustCompile(`[a-zA-Z]`).MatchString(fields.Password) {
		validationErrors["password"] = "Password must contain at least one letter"
	}

	if !regexp.MustCompile(`\d`).MatchString(fields.Password) {
		validationErrors["password"] = "Password must contain at least one number"
	}

	if !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(fields.Password) {
		validationErrors["password"] = "Password must contain at least one special character"
	}

	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	if matched := regexp.MustCompile(emailRegex).MatchString(fields.Email); !matched {
		validationErrors["email"] = "Invalid email address"
	}

	if len(fields.FullName) < 2 || len(fields.FullName) > 50 {
		validationErrors["full_name"] = "Full name must be between 2 and 50 characters"
	}

	fullNameRegex := `^[a-zA-Z\s'-]+$`
	if matched := regexp.MustCompile(fullNameRegex).MatchString(fields.FullName); !matched {
		validationErrors["full_name"] = "Full name can only contain alphabetic characters, spaces, hyphens, and apostrophes"
	}

	return validationErrors
}
