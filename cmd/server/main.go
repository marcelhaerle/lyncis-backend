package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"

	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/handlers"
	"github.com/marcelhaerle/lyncis-backend/internal/middleware"
)

func main() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Using environment variables.")
	}

	// Initialize database connection and auto-migrate GORM schema
	database.Connect()

	// Spin up Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Lyncis Backend Setup and API",
	})

	// Common Middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "*",
	}))
	app.Use(logger.New())  // Request logging
	app.Use(recover.New()) // Panic recovery

	// Define V1 API Group
	api := app.Group("/api/v1")

	// Agent Endpoints (Public)
	agentGroup := api.Group("/agent")
	agentGroup.Post("/register", handlers.RegisterAgent)

	// Agent Endpoints (Authenticated)
	authAgentGroup := api.Group("/agent", middleware.AgentAuth)
	authAgentGroup.Get("/tasks/pending", handlers.GetPendingTask)
	authAgentGroup.Post("/tasks/:task_id/complete", handlers.CompleteTask)
	authAgentGroup.Post("/scans", handlers.SaveScan)

	uiGroup := api.Group("/ui")
	uiGroup.Get("/dashboard", handlers.GetDashboard)
	uiGroup.Get("/findings", handlers.GetFindings)
	uiGroup.Get("/agents", handlers.GetAgents)
	uiGroup.Delete("/agents/:agent_id", handlers.DeleteAgent)
	uiGroup.Post("/agents/:agent_id/scan", handlers.TriggerScan)
	uiGroup.Get("/agents/:agent_id/scans/latest", handlers.GetLatestScan)
	uiGroup.Get("/agents/:agent_id/scans/latest/diff", handlers.GetAgentLatestScanDiff)
	uiGroup.Get("/agents/:agent_id/scans/history", handlers.GetAgentScanHistory)
	// Port configuration
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Start server in a goroutine
	go func() {
		if err := app.Listen(":" + port); err != nil {
			log.Fatalf("Server shutdown with error: %v", err)
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c // Wait for signal
	log.Println("Gracefully shutting down...")
	if err := app.Shutdown(); err != nil {
		log.Fatalf("Error during shutdown: %v", err)
	}

	log.Println("Server exited properly.")
}
