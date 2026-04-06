package models

import (
	"time"

	"github.com/google/uuid"
)

// Task represents a command to be executed by an Agent.
type Task struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	AgentID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"agent_id"`
	Command     string     `gorm:"not null" json:"command"`
	Status      string     `gorm:"default:'pending';not null" json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Relationships
	Agent Agent `gorm:"foreignKey:AgentID;constraint:OnDelete:CASCADE;" json:"-"`
}
