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
	ActivityStatus       string     `json:"activity_status"`
}

// agentWithScan is used for mapping the DB query joining agents and their latest scan
type agentWithScan struct {
	models.Agent
	LatestHardeningIndex *int       `gorm:"column:latest_hardening_index"`
	LatestScanAt         *time.Time `gorm:"column:latest_scan_at"`
	ActivityStatus       string     `gorm:"column:activity_status"`
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

	// Critical Warnings count from latest scans
	warningQuery := `
		SELECT COUNT(*) 
		FROM scan_findings f
		INNER JOIN (
			SELECT DISTINCT ON (agent_id) id
			FROM scans
			ORDER BY agent_id, created_at DESC
		) latest_scans ON f.scan_id = latest_scans.id
		WHERE f.severity = 'warning'
	`
	database.DB.Raw(warningQuery).Scan(&stats.CriticalWarnings)

	return c.JSON(stats)
}

// GetAgents returns a list of all agents, including their computed online status
func GetAgents(c *fiber.Ctx) error {
	var results []agentWithScan

	// Use a LEFT JOIN with a subquery that retrieves the latest scan per agent using DISTINCT ON (agent_id)
	query := `
		SELECT agents.*, 
		       latest_scans.hardening_index AS latest_hardening_index, 
		       latest_scans.created_at AS latest_scan_at,
		       CASE
		           WHEN EXISTS (SELECT 1 FROM tasks WHERE agent_id = agents.id AND status = 'running') THEN 'scanning'
		           WHEN EXISTS (SELECT 1 FROM tasks WHERE agent_id = agents.id AND status = 'pending') THEN 'pending'
		           ELSE 'idle'
		       END AS activity_status
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
			ActivityStatus:       r.ActivityStatus,
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

	// Check if a scan is already running or pending
	var activeTaskCount int64
	if err := database.DB.Model(&models.Task{}).Where("agent_id = ? AND status IN ?", agentID, []string{"pending", "running"}).Count(&activeTaskCount).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to check agent status",
		})
	}

	if activeTaskCount > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "A scan is already scheduled or in progress for this agent",
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

// UIFinding represents a flat structure for displaying findings with agent details in the UI
type UIFinding struct {
	FindingID   uuid.UUID `json:"finding_id"`
	Severity    string    `json:"severity"`
	TestID      string    `json:"test_id"`
	Description string    `json:"description"`
	AgentID     uuid.UUID `json:"agent_id"`
	Hostname    string    `json:"hostname"`
	ScanDate    time.Time `json:"scan_date"`
}

// GetFindings returns an aggregated list of findings from the latest scan of each agent
func GetFindings(c *fiber.Ctx) error {
	var findings []UIFinding
	severityFilter := c.Query("severity")

	// Base query to get findings from the latest scan for each agent, joining with agents and scans
	query := `
		SELECT 
			f.id as finding_id, 
			f.severity, 
			f.test_id, 
			f.description, 
			a.id as agent_id, 
			a.hostname, 
			s.created_at as scan_date
		FROM scan_findings f
		INNER JOIN (
			SELECT DISTINCT ON (agent_id) id, agent_id, created_at
			FROM scans
			ORDER BY agent_id, created_at DESC
		) s ON f.scan_id = s.id
		INNER JOIN agents a ON s.agent_id = a.id
	`

	args := []interface{}{}
	if severityFilter != "" {
		query += " WHERE f.severity = ?"
		args = append(args, severityFilter)
	}

	query += " ORDER BY s.created_at DESC, f.severity DESC"

	if err := database.DB.Raw(query, args...).Scan(&findings).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve findings",
		})
	}

	// Always return an empty array instead of null if there are no findings
	if findings == nil {
		findings = []UIFinding{}
	}

	return c.JSON(findings)
}

// DeleteAgent deletes an agent and all associated tasks, scans, and findings due to CASCADE.
func DeleteAgent(c *fiber.Ctx) error {
	agentIDStr := c.Params("agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent ID format",
		})
	}

	// Check if agent exists and delete
	result := database.DB.Where("id = ?", agentID).Delete(&models.Agent{})
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete agent",
		})
	}

	if result.RowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Agent not found",
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ScanHistoryRecord represents a single point in time for a scan trend
type ScanHistoryRecord struct {
	ScanID          uuid.UUID `json:"scan_id"`
	CreatedAt       time.Time `json:"created_at"`
	HardeningIndex  int       `json:"hardening_index"`
	WarningCount    int64     `json:"warning_count"`
	SuggestionCount int64     `json:"suggestion_count"`
}

// GetAgentScanHistory returns a lightweight, time-ordered array (oldest to newest) of scan history.
func GetAgentScanHistory(c *fiber.Ctx) error {
	agentIDStr := c.Params("agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent ID format",
		})
	}

	var history []ScanHistoryRecord
	query := `
		SELECT 
			s.id as scan_id, 
			s.created_at, 
			s.hardening_index,
			COUNT(CASE WHEN f.severity = 'warning' THEN 1 END) as warning_count,
			COUNT(CASE WHEN f.severity = 'suggestion' THEN 1 END) as suggestion_count
		FROM scans s
		LEFT JOIN scan_findings f ON s.id = f.scan_id
		WHERE s.agent_id = ?
		GROUP BY s.id, s.created_at, s.hardening_index
		ORDER BY s.created_at ASC
	`

	if err := database.DB.Raw(query, agentID).Scan(&history).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve scan history",
		})
	}

	if history == nil {
		history = []ScanHistoryRecord{}
	}

	return c.JSON(history)
}

// GetAgentLatestScanDiff compares the latest scan findings with the previous scan findings
func GetAgentLatestScanDiff(c *fiber.Ctx) error {
	agentIDStr := c.Params("agent_id")
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent ID format",
		})
	}

	var scans []models.Scan
	result := database.DB.Preload("Findings").Where("agent_id = ?", agentID).Order("created_at desc").Limit(2).Find(&scans)
	if result.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve scans",
		})
	}

	// Always ensure empty slices aren't rendered as null in JSON
	newIssues := []models.ScanFinding{}
	resolvedIssues := []models.ScanFinding{}
	unchangedIssues := []models.ScanFinding{}

	if len(scans) == 2 {
		latestScan := scans[0]
		previousScan := scans[1]

		prevFindings := make(map[string]models.ScanFinding)
		for _, f := range previousScan.Findings {
			prevFindings[f.TestID] = f
		}

		latestTestIDs := make(map[string]bool)
		for _, f := range latestScan.Findings {
			latestTestIDs[f.TestID] = true
			if _, exists := prevFindings[f.TestID]; exists {
				unchangedIssues = append(unchangedIssues, f)
			} else {
				newIssues = append(newIssues, f)
			}
		}

		for testID, f := range prevFindings {
			if !latestTestIDs[testID] {
				resolvedIssues = append(resolvedIssues, f)
			}
		}
	} else if len(scans) == 1 {
		// If there is only 1 scan, everything is a "new issue"
		for _, f := range scans[0].Findings {
			newIssues = append(newIssues, f)
		}
	}

	// Null safety for arrays returned to avoid generic react-query crashes
	if newIssues == nil {
		newIssues = []models.ScanFinding{}
	}
	if resolvedIssues == nil {
		resolvedIssues = []models.ScanFinding{}
	}
	if unchangedIssues == nil {
		unchangedIssues = []models.ScanFinding{}
	}

	return c.JSON(fiber.Map{
		"new_issues":       newIssues,
		"resolved_issues":  resolvedIssues,
		"unchanged_issues": unchangedIssues,
	})
}
