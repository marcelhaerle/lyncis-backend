package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

// AgentAuth middleware validates the Authorization Bearer token provided
// by an agent against the database.
func AgentAuth(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Missing or invalid Authorization header",
		})
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token is required",
		})
	}

	// Hash the incoming token
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Look up the agent by token hash
	var agent models.Agent
	result := database.DB.Where("auth_token_hash = ?", tokenHash).First(&agent)
	if result.Error != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token",
		})
	}

	// Store the agent in the request context for downstream handlers to use
	c.Locals("agent", agent)

	return c.Next()
}
