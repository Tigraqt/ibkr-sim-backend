package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	Username          string    `gorm:"unique;not null"`
	Password          string    `gorm:"not null"`
	Email             string    `gorm:"unique;not null"`
	FullName          string    `gorm:"not null"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Balance           float64 `gorm:"default:0"` // starting balance
	ProfilePictureURL string
	Role              string `gorm:"default:'user'"`
}
