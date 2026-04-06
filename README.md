# lyncis-backend

The REST API backend for the Lyncis Security Platform. It receives audit data from `lyncis-agent` instances running on managed hosts, stores results in PostgreSQL, and exposes endpoints for the `lyncis-ui` dashboard.

Built with **Go**, **Fiber v2**, and **GORM**.

---

## Prerequisites

- Go 1.21+
- Docker & Docker Compose (for the local database)

## Developer Setup

### 1. Clone the repository

```bash
git clone https://github.com/marcelhaerle/lyncis-backend.git
cd lyncis-backend
```

### 2. Install dependencies

```bash
go mod download
```

### 3. Start the database

Spin up a PostgreSQL instance using Docker Compose:

```bash
docker compose up -d
```

Then export the connection string:

```bash
export DATABASE_URL="postgres://lyncis:lyncis@localhost:5432/lyncis?sslmode=disable"
```

To stop the database: `docker compose down`. Add `-v` to also remove the persisted volume.

### 4. Run the server

```bash
go run ./cmd/server
```

The server starts on `http://localhost:3000` by default. Database tables are created automatically via GORM AutoMigrate on startup.

## Project Structure

```text
cmd/server/       # Application entrypoint
internal/
  handlers/       # Fiber route handlers
  models/         # GORM models (Agent, Task, Scan, ScanFinding)
  middleware/     # Token authentication middleware
```

## Related Repositories

- [`lyncis-agent`](https://github.com/marcelhaerle/lyncis-agent) — Go binary deployed on managed hosts
- [`lyncis-ui`](https://github.com/marcelhaerle/lyncis-ui) — React dashboard
