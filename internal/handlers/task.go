package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/marcelhaerle/lyncis-backend/internal/database"
	"github.com/marcelhaerle/lyncis-backend/internal/models"
)

type CompleteTaskRequest struct {
	Status string       `json:"status"`
	Error  *interface{} `json:"error"`
}

// GetPendingTask handles GET /api/v1/agent/tasks/pending
func GetPendingTask(c *fiber.Ctx) error {
	db := database.DB
	agentObj := c.Locals("agent")
	if agentObj == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Agent context missing"})
	}
	agent, ok := agentObj.(models.Agent)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Type assertion failed for agent"})
	}

	// Update last_seen
	db.Model(&agent).Update("last_seen", time.Now())

	var task models.Task
	// Find the oldest task with status='pending'
	result := db.Where("agent_id = ? AND status = ?", agent.ID, "pending").Order("created_at asc").First(&task)
	if result.Error != nil {
		// No pending tasks
		return c.SendStatus(fiber.StatusNoContent)
	}

	// Set it to running
	task.Status = "running"
	if err := db.Save(&task).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update task status to running"})
	}

	return c.JSON(fiber.Map{
		"task": fiber.Map{
			"id":      task.ID,
			"command": task.Command,
		},
	})
}

// CompleteTask handles POST /api/v1/agent/tasks/{task_id}/complete
func CompleteTask(c *fiber.Ctx) error {
	db := database.DB
	agentObj := c.Locals("agent")
	if agentObj == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Agent context missing"})
	}
	agent, ok := agentObj.(models.Agent)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Type assertion failed for agent"})
	}

	taskID := c.Params("task_id")

	var req CompleteTaskRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body payload"})
	}

	if req.Status == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Status is required"})
	}

	var task models.Task
	if err := db.Where("id = ? AND agent_id = ?", taskID, agent.ID).First(&task).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Task not found associated with this agent"})
	}

	now := time.Now()
	task.Status = req.Status
	task.CompletedAt = &now

	if err := db.Save(&task).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update task status"})
	}

	return c.SendStatus(fiber.StatusOK)
}
