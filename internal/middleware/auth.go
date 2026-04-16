package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
	"github.com/patrickmn/go-cache"
)

var (
	agentCache = cache.New(5*time.Minute, 10*time.Minute)
)

// AgentAuth middleware validates the Authorization Bearer token provided
// by an agent against the database, with in-memory caching.
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

	// Check cache
	if agent, found := agentCache.Get(tokenHash); found {
		c.Locals("agent", agent.(models.Agent))
		return c.Next()
	}

	// Look up the agent by token hash
	var agent models.Agent
	result := database.DB.Where("auth_token_hash = ?", tokenHash).First(&agent)
	if result.Error != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token",
		})
	}

	// Store in cache
	agentCache.Set(tokenHash, agent, cache.DefaultExpiration)

	// Store the agent in the request context for downstream handlers to use
	c.Locals("agent", agent)

	return c.Next()
}
