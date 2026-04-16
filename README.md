# Lyncis Backend

The core API for the Lyncis Security Platform. It manages agent registration, task dispatching, and audit report ingestion, serving as the bridge between distributed agents and the React dashboard.

Built with **Go**, **Fiber v2**, and **GORM** (PostgreSQL).

---

## Getting Started

### Prerequisites

- [Go 1.21+](https://go.dev/doc/install)
- [Docker & Docker Compose](https://docs.docker.com/compose/)

### 1. Local Development

Start the PostgreSQL container:

```bash
docker compose up -d
```

Set the connection string:

```bash
export DATABASE_URL="postgres://lyncis:lyncis@localhost:5432/lyncis?sslmode=disable"
```

Run the server:

```bash
go run ./cmd/server
```

---

## Architecture & Logic

- **TOFU Registration:** New agents are automatically registered on first contact.
- **Token Security:** Authentication tokens are stored as SHA256 hashes in the DB for security.
- **Database:** Auto-migrates on startup.

## Project Structure

- `cmd/server/`: Application entrypoint.
- `internal/handlers/`: API endpoint logic (Fiber).
- `internal/middleware/`: Security and auth layers.
- `internal/models/`: GORM database schema definitions.

## Configuration (Environment Variables)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | API server port | `3000` |
| `DATABASE_URL` | PostgreSQL connection string | Required |

## Related Repositories

- [`lyncis-agent`](https://github.com/marcelhaerle/lyncis-agent)
- [`lyncis-ui`](https://github.com/marcelhaerle/lyncis-ui)
