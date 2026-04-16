package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/handlers"
	"github.com/marcelhaerle/lyncis-backend/internal/middleware"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

var (
	testApp *fiber.App
	testDB  *gorm.DB
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start PostgreSQL container using testcontainers
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lyncis_test"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		log.Fatalf("failed to start postgres container: %s", err)
	}

	// Ensure container is terminated after tests
	defer func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			log.Fatalf("failed to terminate postgres container: %v", err)
		}
	}()

	// Get database connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %v", err)
	}

	// Connect GORM to the testcontainer instance
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to test database: %v", err)
	}

	// Auto-migrate the models
	if err := db.AutoMigrate(
		&models.Agent{},
		&models.Task{},
		&models.Scan{},
		&models.ScanFinding{},
	); err != nil {
		log.Fatalf("failed to migrate test database: %v", err)
	}

	// Make database available for the application code and tests
	database.DB = db
	testDB = db

	// Setup Fiber App for routing
	testApp = fiber.New()

	api := testApp.Group("/api/v1")
	agentGroup := api.Group("/agent")
	agentGroup.Post("/register", handlers.RegisterAgent)

	authGroup := api.Group("/agent", middleware.AgentAuth)
	authGroup.Get("/tasks/pending", handlers.GetPendingTask)
	authGroup.Post("/tasks/:task_id/complete", handlers.CompleteTask)

	uiGroup := api.Group("/ui")
	uiGroup.Get("/dashboard", handlers.GetDashboard)
	uiGroup.Get("/agents", handlers.GetAgents)
	uiGroup.Delete("/agents/:agent_id", handlers.DeleteAgent)
	uiGroup.Post("/agents/:agent_id/scan", handlers.TriggerScan)
	uiGroup.Get("/agents/:agent_id/scans/latest", handlers.GetLatestScan)
	uiGroup.Get("/agents/:agent_id/scans/latest/diff", handlers.GetAgentLatestScanDiff)
	uiGroup.Get("/agents/:agent_id/scans/history", handlers.GetAgentScanHistory)
	uiGroup.Get("/findings", handlers.GetFindings)
	os.Exit(m.Run())
}

func TestRegisterAgent_Success(t *testing.T) {
	payload := map[string]string{
		"hostname": "test-server-01",
		"os_info":  "Ubuntu 22.04",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "/api/v1/agent/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	if resp.StatusCode != fiber.StatusCreated {
		t.Errorf("Expected status %d, got %d", fiber.StatusCreated, resp.StatusCode)
	}

	// Parse Response
	var result handlers.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.AgentID == "" || result.Token == "" {
		t.Errorf("Expected AgentID and Token, got empty values")
	}

	// Verify it was correctly saved in DB
	var agent models.Agent
	if err := testDB.Where("hostname = ?", "test-server-01").First(&agent).Error; err != nil {
		t.Fatalf("Agent not found in database: %v", err)
	}
}

func TestRegisterAgent_MissingHostname(t *testing.T) {
	payload := map[string]string{
		"os_info": "Ubuntu 22.04", // Missing hostname
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "/api/v1/agent/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	if resp.StatusCode != fiber.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", fiber.StatusBadRequest, resp.StatusCode)
	}
}

func TestRegisterAgent_Conflict(t *testing.T) {
	// Pre-seed an agent into the DB
	testDB.Create(&models.Agent{
		Hostname:      "test-server-conflict",
		AuthTokenHash: "dummyhash",
	})

	payload := map[string]string{
		"hostname": "test-server-conflict",
		"os_info":  "Ubuntu 22.04",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "/api/v1/agent/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	// Make request trying to register the same hostname again
	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

func TestRegisterAgent_LongInputs(t *testing.T) {
	// Generate string longer than 255 characters
	longString := ""
	for i := 0; i < 256; i++ {
		longString += "a"
	}

	payload := map[string]string{
		"hostname": longString,
		"os_info":  longString,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", "/api/v1/agent/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	// This should fail because GORM will attempt to truncate or reject the string 
	// based on the database column type/constraint if validation is enabled,
	// but mostly we want to ensure the backend returns a reasonable error.
	resp, err := testApp.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}

	// Expecting 500 or 400 depending on how GORM handles the constraint violation
	if resp.StatusCode != fiber.StatusInternalServerError && resp.StatusCode != fiber.StatusBadRequest {
		t.Errorf("Expected status 500 or 400 due to database constraint violation, got %d", resp.StatusCode)
	}
}
