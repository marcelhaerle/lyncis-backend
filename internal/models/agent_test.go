package models_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
	"github.com/stretchr/testify/assert"
)

// We cannot easily test GORM constraints without a real DB, 
// but we can verify the model struct tags at least exist if needed 
// or run a basic integration test if we have a test DB.
// Since we don't have a live DB for this unit test context,
// we'll stick to a conceptual structure check.

func TestAgentModelFields(t *testing.T) {
	// Example: Verify we can instantiate
	agent := models.Agent{
		ID:       uuid.New(),
		Hostname: "test-host",
	}
	assert.Equal(t, "test-host", agent.Hostname)
}
