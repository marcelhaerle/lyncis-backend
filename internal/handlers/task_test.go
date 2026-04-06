package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"

	// To hash the token appropriately:
	"crypto/sha256"
	"encoding/hex"
)

func createTestAgent(hostname string, rawToken string) models.Agent {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	agent := models.Agent{
		ID:            uuid.New(),
		Hostname:      hostname,
		AuthTokenHash: tokenHash,
		Status:        "online",
		LastSeen:      time.Now(),
	}

	database.DB.Create(&agent)
	return agent
}

func createTestTask(agentID uuid.UUID, command string) models.Task {
	task := models.Task{
		ID:      uuid.New(),
		AgentID: agentID,
		Command: command,
		Status:  "pending",
	}

	database.DB.Create(&task)
	return task
}

func TestGetPendingTask_Success(t *testing.T) {
	// Cleanup tasks
	database.DB.Exec("DELETE FROM tasks")
	database.DB.Exec("DELETE FROM agents")

	rawToken := "my-secret-token"
	agent := createTestAgent("agent-01", rawToken)
	task := createTestTask(agent.ID, "run_lynis")

	req, _ := http.NewRequest("GET", "/api/v1/agent/tasks/pending", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var result struct {
		Task struct {
			ID      string `json:"id"`
			Command string `json:"command"`
		} `json:"task"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed decoding response body: %v", err)
	}

	if result.Task.ID != task.ID.String() {
		t.Errorf("Expected task ID %s, got %s", task.ID.String(), result.Task.ID)
	}

	if result.Task.Command != "run_lynis" {
		t.Errorf("Expected command run_lynis, got %s", result.Task.Command)
	}

	// Verify task status is 'running'
	var updatedTask models.Task
	database.DB.Where("id = ?", task.ID).First(&updatedTask)
	if updatedTask.Status != "running" {
		t.Errorf("Expected task status to be running, got %s", updatedTask.Status)
	}
}

func TestGetPendingTask_NoContent(t *testing.T) {
	database.DB.Exec("DELETE FROM tasks")
	database.DB.Exec("DELETE FROM agents")

	rawToken := "my-secret-token"
	createTestAgent("agent-no-task", rawToken)

	req, _ := http.NewRequest("GET", "/api/v1/agent/tasks/pending", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	if resp.StatusCode != fiber.StatusNoContent {
		t.Errorf("Expected status %d, got %d", fiber.StatusNoContent, resp.StatusCode)
	}
}

func TestCompleteTask_Success(t *testing.T) {
	database.DB.Exec("DELETE FROM tasks")
	database.DB.Exec("DELETE FROM agents")

	rawToken := "my-secret-token"
	agent := createTestAgent("agent-02", rawToken)
	task := createTestTask(agent.ID, "run_lynis")

	// Task must be running first usually, but `CompleteTask` just updates state
	// let's set it up as completed to see if it updates
	payload := map[string]interface{}{
		"status": "completed",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "/api/v1/agent/tasks/"+task.ID.String()+"/complete", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var updatedTask models.Task
	database.DB.Where("id = ?", task.ID).First(&updatedTask)
	if updatedTask.Status != "completed" {
		t.Errorf("Expected task status to be completed, got %s", updatedTask.Status)
	}
	if updatedTask.CompletedAt == nil {
		t.Errorf("Expected CompletedAt to be set")
	}
}
