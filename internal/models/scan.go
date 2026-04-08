package models

import (
	"time"

	"github.com/google/uuid"
)

// Scan represents a Lynis scan executed by an agent.
type Scan struct {
	ID             uuid.UUID     `gorm:"type:uuid;primaryKey" json:"id"`
	AgentID        uuid.UUID     `gorm:"type:uuid;index;not null" json:"agent_id"`
	HardeningIndex int           `json:"hardening_index"`
	RawData        string        `gorm:"type:jsonb" json:"raw_data"`
	CreatedAt      time.Time     `json:"created_at"`
	Findings       []ScanFinding `gorm:"foreignKey:ScanID;constraint:OnDelete:CASCADE;" json:"findings"`
}

// ScanFinding represents a specific warning or suggestion from a scan.
type ScanFinding struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ScanID      uuid.UUID `gorm:"type:uuid;index;not null" json:"scan_id"`
	AgentID     uuid.UUID `gorm:"type:uuid" json:"agent_id"`
	Severity    string    `json:"severity"` // 'warning', 'suggestion'
	TestID      string    `json:"test_id"`  // e.g. "SSH-7408"
	Description string    `json:"description"`
}
