package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Hostname string `json:"hostname"`
	OSInfo   string `json:"os_info"`
}

type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

// RegisterAgent handles the POST /api/v1/agent/register endpoint.
// It implements a "Trust On First Use" (TOFU) policy.
func RegisterAgent(c *fiber.Ctx) error {
	req := new(RegisterRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body payload",
		})
	}

	if req.Hostname == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Hostname is required for registration",
		})
	}

	// Wait for global database driver instance
	db := database.DB

	// Lookup agent by hostname
	var existingAgent models.Agent
	result := db.Where("hostname = ?", req.Hostname).First(&existingAgent)
	
	if result.Error == nil {
		// Agent already exists: enforce trust on first use securely
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Agent is already registered",
		})
	} else if result.Error != gorm.ErrRecordNotFound {
		// Unhandled database error
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to query agent table",
		})
	}

	// Agent does not exist: generate a secure raw token
	rawToken := uuid.New().String()
	
	// Hash the raw token for secure DB storage
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Instantiate new agent
	newAgent := models.Agent{
		ID:            uuid.New(),
		Hostname:      req.Hostname,
		OSInfo:        req.OSInfo,
		Status:        "online",
		LastSeen:      time.Now(),
		AuthTokenHash: tokenHash,
	}

	// Persist to database
	if err := db.Create(&newAgent).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register new agent",
		})
	}

	// Respond with agent ID and the unhashed plain token exactly once
	return c.Status(fiber.StatusCreated).JSON(RegisterResponse{
		AgentID: newAgent.ID.String(),
		Token:   rawToken,
	})
}
