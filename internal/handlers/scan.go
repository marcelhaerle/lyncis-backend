package handlers

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

type ScanFindingPayload struct {
	Severity    string `json:"severity"`
	TestID      string `json:"test_id"`
	Description string `json:"description"`
}

type SaveScanRequest struct {
	HardeningIndex int                    `json:"hardening_index"`
	RawData        map[string]interface{} `json:"raw_data"`
	Findings       []ScanFindingPayload   `json:"findings"`
}

// SaveScan handles the POST /api/v1/agent/scans endpoint.
func SaveScan(c *fiber.Ctx) error {
	agentObj := c.Locals("agent")
	if agentObj == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	agent := agentObj.(models.Agent)

	req := new(SaveScanRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	rawDataBytes, err := json.Marshal(req.RawData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process raw_data"})
	}

	scanID := uuid.New()
	scan := models.Scan{
		ID:             scanID,
		AgentID:        agent.ID,
		HardeningIndex: req.HardeningIndex,
		RawData:        string(rawDataBytes),
		CreatedAt:      time.Now(),
	}

	var findings []models.ScanFinding
	for _, f := range req.Findings {
		findings = append(findings, models.ScanFinding{
			ID:          uuid.New(),
			ScanID:      scanID,
			AgentID:     agent.ID,
			Severity:    f.Severity,
			TestID:      f.TestID,
			Description: f.Description,
		})
	}
	scan.Findings = findings

	if err := database.DB.Create(&scan).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save scan"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Scan saved successfully",
		"id":      scan.ID.String(),
	})
}
