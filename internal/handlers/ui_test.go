package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/marcelhaerle/lyncis-backend/internal/handlers"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

func TestGetDashboard(t *testing.T) {
	// Clean DB state
	testDB.Exec("TRUNCATE TABLE scan_findings, scans, tasks, agents RESTART IDENTITY CASCADE")

	agent1ID := uuid.New()
	agent2ID := uuid.New()
	scan1ID := uuid.New()
	scan2ID := uuid.New()

	// Seed agents
	// Agent 1: online (last seen now)
	agent1 := &models.Agent{
		ID:            agent1ID,
		Hostname:      "ui-agent-01",
		OSInfo:        "Debian 12",
		Status:        "online",
		LastSeen:      time.Now(),
		AuthTokenHash: "hash1",
	}
	// Agent 2: offline (last seen 10 mins ago)
	agent2 := &models.Agent{
		ID:            agent2ID,
		Hostname:      "ui-agent-02",
		OSInfo:        "Ubuntu 20.04",
		Status:        "offline",
		LastSeen:      time.Now().Add(-10 * time.Minute),
		AuthTokenHash: "hash2",
	}
	testDB.Create(agent1)
	testDB.Create(agent2)

	// Seed scans and findings
	// Scan 1: hardening 60
	scan1 := &models.Scan{
		ID:             scan1ID,
		AgentID:        agent1ID,
		HardeningIndex: 60,
		RawData:        "{}",
		CreatedAt:      time.Now().Add(-5 * time.Minute),
	}
	// Scan 2: hardening 80
	scan2 := &models.Scan{
		ID:             scan2ID,
		AgentID:        agent2ID,
		HardeningIndex: 80,
		RawData:        "{}",
		CreatedAt:      time.Now(),
	}
	testDB.Create(scan1)
	testDB.Create(scan2)

	// Critical warning for Scan 1
	finding1 := &models.ScanFinding{
		ID:          uuid.New(),
		ScanID:      scan1ID,
		AgentID:     agent1ID,
		Severity:    "warning",
		TestID:      "TEST-01",
		Description: "Critical security issue",
	}
	// Suggestion for Scan 2
	finding2 := &models.ScanFinding{
		ID:          uuid.New(),
		ScanID:      scan2ID,
		AgentID:     agent2ID,
		Severity:    "suggestion",
		TestID:      "TEST-02",
		Description: "Consider updating",
	}
	testDB.Create(finding1)
	testDB.Create(finding2)

	// Make request
	req := httptest.NewRequest("GET", "/api/v1/ui/dashboard", nil)
	resp, _ := testApp.Test(req, -1)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var stats handlers.DashboardStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if stats.TotalAgents != 2 {
		t.Errorf("expected 2 total agents, got %d", stats.TotalAgents)
	}
	if stats.OnlineAgents != 1 {
		t.Errorf("expected 1 online agent, got %d", stats.OnlineAgents)
	}
	if stats.AvgHardeningIndex != 70 {
		t.Errorf("expected avg hardening index 70, got %f", stats.AvgHardeningIndex)
	}
	if stats.CriticalWarnings != 1 {
		t.Errorf("expected 1 critical warning, got %d", stats.CriticalWarnings)
	}
}

func TestGetAgents(t *testing.T) {
	testDB.Exec("TRUNCATE TABLE scan_findings, scans, tasks, agents RESTART IDENTITY CASCADE")

	agentID := uuid.New()
	agent := &models.Agent{
		ID:            agentID,
		Hostname:      "ui-test-agent",
		OSInfo:        "CentOS 8",
		Status:        "online",
		LastSeen:      time.Now(),
		AuthTokenHash: "hash-agent",
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now(),
	}
	testDB.Create(agent)

	scanID := uuid.New()
	scan := &models.Scan{
		ID:             scanID,
		AgentID:        agentID,
		HardeningIndex: 85,
		RawData:        "{}",
		CreatedAt:      time.Now().Add(-5 * time.Minute),
	}
	testDB.Create(scan)

	// An older scan to ensure only the latest is picked
	olderScan := &models.Scan{
		ID:             uuid.New(),
		AgentID:        agentID,
		HardeningIndex: 40,
		RawData:        "{}",
		CreatedAt:      time.Now().Add(-10 * time.Minute),
	}
	testDB.Create(olderScan)

	// Test tasks for activity status
	// Agent 1 has a running task
	taskID := uuid.New()
	task := &models.Task{
		ID:        taskID,
		AgentID:   agentID,
		Command:   "run_lynis",
		Status:    "running",
		CreatedAt: time.Now(),
	}
	testDB.Create(task)

	req := httptest.NewRequest("GET", "/api/v1/ui/agents", nil)
	resp, _ := testApp.Test(req, -1)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var agents []handlers.UIAgent
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if !agents[0].Online {
		t.Errorf("expected agent to be marked as online")
	}
	if agents[0].LatestHardeningIndex == nil || *agents[0].LatestHardeningIndex != 85 {
		t.Errorf("expected latest_hardening_index to be 85, got %v", agents[0].LatestHardeningIndex)
	}
	if agents[0].LatestScanAt == nil {
		t.Errorf("expected latest_scan_at to not be nil")
	}
	if agents[0].ActivityStatus != "scanning" {
		t.Errorf("expected activity_status to be scanning, got %s", agents[0].ActivityStatus)
	}
}

func TestTriggerScan(t *testing.T) {
	testDB.Exec("TRUNCATE TABLE scan_findings, scans, tasks, agents RESTART IDENTITY CASCADE")

	agentID := uuid.New()
	testDB.Create(&models.Agent{
		ID:            agentID,
		Hostname:      "trigger-target",
		AuthTokenHash: "hash-trigger",
	})

	req := httptest.NewRequest("POST", "/api/v1/ui/agents/"+agentID.String()+"/scan", bytes.NewBuffer([]byte{}))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := testApp.Test(req, -1)

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", resp.StatusCode)
	}

	var task models.Task
	if err := testDB.First(&task, "agent_id = ?", agentID).Error; err != nil {
		t.Fatalf("task was not created in db")
	}
	if task.Command != "run_lynis" {
		t.Errorf("expected command run_lynis, got %s", task.Command)
	}
	if task.Status != "pending" {
		t.Errorf("expected status pending, got %s", task.Status)
	}

	// Trigger second scan to test conflict
	req2 := httptest.NewRequest("POST", "/api/v1/ui/agents/"+agentID.String()+"/scan", bytes.NewBuffer([]byte{}))
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := testApp.Test(req2, -1)

	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("expected status 409 conflict, got %d", resp2.StatusCode)
	}
}

func TestGetLatestScan(t *testing.T) {
	testDB.Exec("TRUNCATE TABLE scan_findings, scans, tasks, agents RESTART IDENTITY CASCADE")

	agentID := uuid.New()
	testDB.Create(&models.Agent{
		ID:            agentID,
		Hostname:      "latest-scan-target",
		AuthTokenHash: "hash-latest-scan",
	})

	oldScanID := uuid.New()
	oldScan := &models.Scan{
		ID:             oldScanID,
		AgentID:        agentID,
		HardeningIndex: 50,
		RawData:        "{}",
		CreatedAt:      time.Now().Add(-10 * time.Minute),
	}
	newScanID := uuid.New()
	newScan := &models.Scan{
		ID:             newScanID,
		AgentID:        agentID,
		HardeningIndex: 85,
		RawData:        "{}",
		CreatedAt:      time.Now(),
	}
	testDB.Create(oldScan)
	testDB.Create(newScan)

	testDB.Create(&models.ScanFinding{
		ID:          uuid.New(),
		ScanID:      newScanID,
		AgentID:     agentID,
		Severity:    "warning",
		Description: "A warning detail",
	})

	req := httptest.NewRequest("GET", "/api/v1/ui/agents/"+agentID.String()+"/scans/latest", nil)
	resp, _ := testApp.Test(req, -1)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var res models.Scan
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.ID != newScanID {
		t.Errorf("expected new scan ID %s, got %s", newScanID.String(), res.ID.String())
	}
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(res.Findings))
	}
}

func TestGetFindings(t *testing.T) {
	// Clean DB state
	testDB.Exec("TRUNCATE TABLE scan_findings, scans, tasks, agents RESTART IDENTITY CASCADE")

	agent1ID := uuid.New()

	// Agent 1
	agent1 := &models.Agent{
		ID:            agent1ID,
		Hostname:      "ui-agent-01",
		OSInfo:        "Debian 12",
		Status:        "online",
		LastSeen:      time.Now(),
		AuthTokenHash: "hash1",
	}
	testDB.Create(agent1)

	// Agent 1 - Old Scan
	oldScanID := uuid.New()
	oldScan := &models.Scan{
		ID:             oldScanID,
		AgentID:        agent1ID,
		HardeningIndex: 50,
		RawData:        "{}",
		CreatedAt:      time.Now().Add(-10 * time.Minute),
	}
	testDB.Create(oldScan)

	// Find in old scan (should NOT be returned)
	testDB.Create(&models.ScanFinding{
		ID:          uuid.New(),
		ScanID:      oldScanID,
		AgentID:     agent1ID,
		Severity:    "warning",
		TestID:      "TEST-OLD",
		Description: "Old issue",
	})

	// Agent 1 - Latest Scan
	latestScanID := uuid.New()
	latestScan := &models.Scan{
		ID:             latestScanID,
		AgentID:        agent1ID,
		HardeningIndex: 80,
		RawData:        "{}",
		CreatedAt:      time.Now().Add(-1 * time.Minute),
	}
	testDB.Create(latestScan)

	// Findings in latest scan (SHOULD be returned)
	warningID := uuid.New()
	testDB.Create(&models.ScanFinding{
		ID:          warningID,
		ScanID:      latestScanID,
		AgentID:     agent1ID,
		Severity:    "warning",
		TestID:      "TEST-LATEST-WARN",
		Description: "New issue",
	})
	testDB.Create(&models.ScanFinding{
		ID:          uuid.New(),
		ScanID:      latestScanID,
		AgentID:     agent1ID,
		Severity:    "suggestion",
		TestID:      "TEST-SUGG",
		Description: "New suggestion",
	})

	t.Run("Filter by severity=warning", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/ui/findings?severity=warning", nil)
		resp, _ := testApp.Test(req, -1)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		var res []handlers.UIFinding
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Should only return 1 warning from the LATEST scan
		if len(res) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(res))
		}

		if res[0].FindingID != warningID {
			t.Errorf("expected finding ID %s, got %s", warningID.String(), res[0].FindingID.String())
		}
		if res[0].Severity != "warning" {
			t.Errorf("expected severity 'warning', got %s", res[0].Severity)
		}
	})

	t.Run("No filter", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/ui/findings", nil)
		resp, _ := testApp.Test(req, -1)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		var res []handlers.UIFinding
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Should return 2 findings (warning + suggestion) from the LATEST scan
		if len(res) != 2 {
			t.Fatalf("expected 2 findings, got %d", len(res))
		}
	})
}

func TestDeleteAgent(t *testing.T) {
	testDB.Exec("TRUNCATE TABLE scan_findings, scans, tasks, agents RESTART IDENTITY CASCADE")

	// 1. Create agent
	agentID := uuid.New()
	testDB.Exec("INSERT INTO agents (id, hostname, os_info, status, last_seen, auth_token_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		agentID, "delete-agent", "OS", "online", time.Now(), "hash", time.Now(), time.Now())

	// Test case: Agent exists
	req := httptest.NewRequest("DELETE", "/api/v1/ui/agents/"+agentID.String(), nil)
	resp, _ := testApp.Test(req, -1)

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Verify agent was deleted
	var count int64
	testDB.Model(&models.Agent{}).Where("id = ?", agentID).Count(&count)
	if count != 0 {
		t.Errorf("Expected 0 agents, found %d", count)
	}

	// Test case: Agent does not exist
	nonExistentID := uuid.New().String()
	req = httptest.NewRequest("DELETE", "/api/v1/ui/agents/"+nonExistentID, nil)
	resp, _ = testApp.Test(req, -1)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}

	// Test case: Invalid UUID format
	req = httptest.NewRequest("DELETE", "/api/v1/ui/agents/invalid-id", nil)
	resp, _ = testApp.Test(req, -1)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}
