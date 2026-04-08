package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/handlers"
	"github.com/marcelhaerle/lyncis-backend/internal/middleware"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

func TestSaveScan_Success(t *testing.T) {
	app := fiber.New()
	database.DB.Exec("DELETE FROM scan_findings")
	database.DB.Exec("DELETE FROM scans")
	database.DB.Exec("DELETE FROM agents")

	rawToken := uuid.New().String()
	agent := createTestAgent("scan-agent-1", rawToken)

	app.Post("/api/v1/agent/scans", middleware.AgentAuth, handlers.SaveScan)

	reqBody := handlers.SaveScanRequest{
		HardeningIndex: 72,
		RawData: map[string]interface{}{
			"os":      "Ubuntu",
			"version": "22.04",
		},
		Findings: []handlers.ScanFindingPayload{
			{Severity: "warning", TestID: "TEST-01", Description: "A warning"},
			{Severity: "suggestion", TestID: "TEST-02", Description: "A suggestion"},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/v1/agent/scans", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rawToken)

	resp, err := app.Test(req, -1)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, resp.StatusCode)

	var scan models.Scan
	result := database.DB.Preload("Findings").First(&scan, "agent_id = ?", agent.ID)
	assert.NoError(t, result.Error)
	assert.Equal(t, 72, scan.HardeningIndex)
	assert.Equal(t, 2, len(scan.Findings))
}

func TestSaveScan_Unauthorized(t *testing.T) {
	app := fiber.New()
	app.Post("/api/v1/agent/scans", middleware.AgentAuth, handlers.SaveScan)

	reqBody := handlers.SaveScanRequest{}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/v1/agent/scans", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token")

	resp, _ := app.Test(req, -1)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}
