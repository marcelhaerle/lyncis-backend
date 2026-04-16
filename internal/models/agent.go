package models

import (
	"time"

	"github.com/google/uuid"
)

// Agent represents a managed host in the Lyncis Security Platform.
type Agent struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Hostname      string    `gorm:"uniqueIndex;not null;size:255" json:"hostname"`
	OSInfo        string    `gorm:"size:255" json:"os_info"`
	Status        string    `gorm:"default:'online'" json:"status"`
	LastSeen      time.Time `json:"last_seen"`
	AuthTokenHash string    `gorm:"not null;uniqueIndex" json:"-"` // Hash of the token, '-' ensures it's never serialized in JSON responses
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
