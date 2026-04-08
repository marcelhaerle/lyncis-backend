package handlers

import (
	"math"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

// DashboardStats represents the aggregated dashboard statistics
type DashboardStats struct {
	TotalAgents       int64   `json:"total_agents"`
	OnlineAgents      int64   `json:"online_agents"`
	AvgHardeningIndex float64 `json:"avg_hardening_index"`
	CriticalWarnings  int64   `json:"critical_warnings"`
}

// UIAgent is a wrapper to append computed properties for an Agent
type UIAgent struct {
	models.Agent
	Online               bool       `json:"online"`
	LatestHardeningIndex *int       `json:"latest_hardening_index"`
	LatestScanAt         *time.Time `json:"latest_scan_at"`
}

// agentWithScan is used for mapping the DB query joining agents and their latest scan
type agentWithScan struct {
	models.Agent
	LatestHardeningIndex *int       `gorm:"column:latest_hardening_index"`
	LatestScanAt         *time.Time `gorm:"column:latest_scan_at"`
}

// GetDashboard returns aggregated statistics for the UI dashboard
func GetDashboard(c *fiber.Ctx) error {
	var stats DashboardStats

	// Total Agents count
	database.DB.Model(&models.Agent{}).Count(&stats.TotalAgents)

	// Online Agents count
	timeThreshold := time.Now().Add(-3 * time.Minute)
	database.DB.Model(&models.Agent{}).Where("last_seen > ?", timeThreshold).Count(&stats.OnlineAgents)

	// Average Hardening Index
	var avgHardening struct {
		Avg float64
	}
	database.DB.Model(&models.Scan{}).Select("COALESCE(AVG(hardening_index), 0) as avg").Scan(&avgHardening)
	stats.AvgHardeningIndex = math.Round(avgHardening.Avg)

	// Critical Warnings count
	database.DB.Model(&models.ScanFinding{}).Where("severity = ?", "warning").Count(&stats.CriticalWarnings)

	return c.JSON(stats)
}

// GetAgents returns a list of all agents, including their computed online status
func GetAgents(c *fiber.Ctx) error {
	var results []agentWithScan

	// Use a LEFT JOIN with a subquery that retrieves the latest scan per agent using DISTINCT ON (agent_id)
	query := `
		SELECT agents.*, latest_scans.hardening_index AS latest_hardening_index, latest_scans.created_at AS latest_scan_at
		FROM agents
		LEFT JOIN (
			SELECT DISTINCT ON (agent_id) agent_id, hardening_index, created_at
			FROM scans
			ORDER BY agent_id, created_at DESC
		) latest_scans ON agents.id = latest_scans.agent_id
		ORDER BY agents.created_at DESC
	`

	if err := database.DB.Raw(query).Scan(&results).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve agents",
		})
	}

	timeThreshold := time.Now().Add(-3 * time.Minute)
	uiAgents := make([]UIAgent, len(results))
	for i, r := range results {
		uiAgents[i] = UIAgent{
			Agent:                r.Agent,
			Online:               r.Agent.LastSeen.After(timeThreshold),
			LatestHardeningIndex: r.LatestHardeningIndex,
			LatestScanAt:         r.LatestScanAt,
		}
	}

	return c.JSON(uiAgents)
}

// TriggerScan queues a new run_lynis task for a specific agent
func TriggerScan(c *fiber.Ctx) error {
	agentIDStr := c.Params("agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent ID format",
		})
	}

	// Verify agent exists
	var agent models.Agent
	if err := database.DB.First(&agent, "id = ?", agentID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Agent not found",
		})
	}

	task := models.Task{
		ID:        uuid.New(),
		AgentID:   agentID,
		Command:   "run_lynis",
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	if err := database.DB.Create(&task).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create task",
		})
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"message": "Scan queued successfully",
		"task_id": task.ID,
	})
}

// GetLatestScan returns the most recent scan findings for a specific agent
func GetLatestScan(c *fiber.Ctx) error {
	agentIDStr := c.Params("agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent ID format",
		})
	}

	var scan models.Scan
	result := database.DB.Preload("Findings").Where("agent_id = ?", agentID).Order("created_at desc").First(&scan)
	if result.Error != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "No scan found for this agent",
		})
	}

	return c.JSON(scan)
}
