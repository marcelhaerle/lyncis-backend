package database

import (
	"log"
	"os"

	"github.com/marcelhaerle/lyncis-backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB represents the active database connection
var DB *gorm.DB

// Connect initializes the database connection and runs GORM auto-migrations.
func Connect() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is not set. Please set it before running the server.")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Successfully connected to the database")

	// Auto-migrate tables
	err = db.AutoMigrate(
		&models.Agent{},
		// Additional models like Task, Scan, ScanFinding will be added here
	)
	if err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	log.Println("Database migrations completed")
	DB = db
}
