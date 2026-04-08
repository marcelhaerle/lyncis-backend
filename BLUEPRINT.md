# Lyncis Security Platform - Implementation Blueprint

## 1. System Overview & Repositories

The project consists of three separate repositories, each producing their own Docker images:

1. `lyncis-backend` (Go / Fiber / PostgreSQL)
2. `lyncis-agent` (Go / statically compiled binary)
3. `lyncis-ui` (React / Vite / Tailwind CSS)

This project is the `lyncis-backend`.

---

## 2. Database Schema (PostgreSQL)

All tables belong to a single-tenant instance. The Go backend uses GORM for auto-migration.

### Table: agents

* `id` (UUID, Primary Key)
* `hostname` (String, Unique, Not Null)
* `os_info` (String)
* `status` (String: 'online', 'offline')
* `last_seen` (Timestamp)
* `auth_token_hash` (String) - Hash of the token given to the agent upon registration.

### Table: tasks

* `id` (UUID, Primary Key)
* `agent_id` (UUID, Foreign Key -> agents.id, Index)
* `command` (String) - e.g. "run_lynis"
* `status` (String: 'pending', 'running', 'completed', 'failed')
* `created_at` (Timestamp)
* `completed_at` (Timestamp, Nullable)

### Table: scans

* `id` (UUID, Primary Key)
* `agent_id` (UUID, Foreign Key -> agents.id, Index)
* `hardening_index` (Integer)
* `raw_data` (JSONB) - The complete Lynis output as key-value pairs
* `created_at` (Timestamp)

### Table: scan_findings

* `id` (UUID, Primary Key)
* `scan_id` (UUID, Foreign Key -> scans.id, Index, OnDelete Cascade)
* `agent_id` (UUID, Foreign Key -> agents.id)
* `severity` (String: 'warning', 'suggestion')
* `test_id` (String) - e.g. "SSH-7408"
* `description` (String)

---

## 3. API Specification (Backend REST)

### 3.1 Agent Communication (Endpoints for the Go Binary)

All endpoints (except Register) require the header: `Authorization: Bearer <token>`

* **POST /api/v1/agent/register**
  * **Request:** `{ "hostname": "server-01", "os_info": "Ubuntu 22.04" }`
  * **Logic:** Look up agent by hostname. If not found -> create. Generate a secure `token` (e.g. UUID v4), store its hash in the DB.
  * **Response:** `{ "agent_id": "<uuid>", "token": "<raw_token>" }`
* **GET /api/v1/agent/tasks/pending**
  * **Logic:** Update `last_seen` for the requesting agent. Find the oldest task with status='pending'. Set it to 'running'.
  * **Response:** `{ "task": { "id": "<uuid>", "command": "run_lynis" } }` (or 204 No Content if nothing is pending)
* **POST /api/v1/agent/tasks/{task_id}/complete**
  * **Request:** `{ "status": "completed", "error": null }`
* **POST /api/v1/agent/scans**
  * **Request:** `{ "hardening_index": 65, "raw_data": { ... }, "findings": [ {"severity": "warning", "test_id": "...", "description": "..."} ] }`
  * **Logic:** Saves the scan and iterates over the findings to store them in `scan_findings`.

### 3.2 UI Communication (Endpoints for React)

* **GET /api/v1/ui/dashboard**
  * **Response:** `{ "total_agents": 5, "online_agents": 4, "avg_hardening_index": 68, "critical_warnings": 12 }`
* **GET /api/v1/ui/agents**
  * **Response:** List of all agents including computed status (online = `last_seen` < 3 minutes ago).
* **POST /api/v1/ui/agents/{agent_id}/scan**
  * **Logic:** Creates a new task with command='run_lynis' and status='pending'.
* **GET /api/v1/ui/agents/{agent_id}/scans/latest**
  * **Response:** The most recent scan including findings.

---

## 4. Implementation Roadmap (Features)

IMPORTANT for the AI agent: Implement features strictly in order. No mocking of DB calls — use the final architecture immediately.
Create unit and integration tests where possible. Document the code and implementation decisions. Produce high quality code.

### Feature 1: Backend Setup & Agent Registration

* **Repository:** `lyncis-backend`
* **Tasks:**
  1. Set up Go project, Fiber framework and GORM (Postgres).
  2. Implement the database models `Agent` and GORM AutoMigrate.
  3. Implement `POST /api/v1/agent/register` (trust on first use, return the plain token, store the hash).

### Feature 2: Agent CLI & Registration Flow

* **Repository:** `lyncis-agent`
* **Tasks:**
  1. Set up Go project.
  2. Implement a function to read the hostname.
  3. Implement HTTP call to the backend (`/register`).
  4. Save the returned token locally at `/etc/lyncis/config.json` (or in the current directory for dev).

### Feature 3: Task Polling System (Heartbeat)

* **Repository:** `lyncis-backend` & `lyncis-agent`
* **Backend:** Implement `GET /api/v1/agent/tasks/pending` and middleware for token validation (compare against hash in DB).
* **Agent:** Implement a ticker goroutine (every 10 seconds). Make request to backend. If 204, wait. If 200, process the task.

### Feature 4: Lynis Execution & Parsing

* **Repository:** `lyncis-agent`
* **Tasks:**
  1. When task `run_lynis` is received, execute `exec.Command("lynis", "audit", "system", "--cronjob")`.
  2. Write a parser for `/var/log/lynis-report.dat`.
  3. Extract key-value pairs. Look specifically for keys starting with `warning[]=` or `suggestion[]=`, and format them as a findings array.
  4. Send payload to `POST /api/v1/agent/scans` and mark the task as completed.

### Feature 5: Backend UI Endpoints

* **Repository:** `lyncis-backend`
* **Tasks:**
  1. Implement `GET /api/v1/ui/dashboard` (aggregation via SQL COUNT/AVG).
  2. Implement `GET /api/v1/ui/agents` (GORM Find).
  3. Implement `POST /api/v1/ui/agents/{agent_id}/scan` (create task in DB).

### Feature 6: React UI - Core & Layout

* **Repository:** `lyncis-ui`
* **Tasks:**
  1. Set up React Router.
  2. Create a layout with a sidebar (links: Dashboard, Agents).
  3. Configure Tailwind CSS with a Sci-Fi palette (Background: `#09090b`, Primary: `#06b6d4`, Surface: `#18181b`, Border: `#27272a`).
  4. Create Axios client in `src/api/client.ts`.

### Feature 7: React UI - Agent Management & Dashboard

* **Repository:** `lyncis-ui`
* **Tasks:**
  1. **Dashboard View:** Load `/dashboard` stats and display them as grid cards.
  2. **Agent View:** Load `/agents`. Display table with hostname, OS, status (green/red dot based on "online").
  3. Add a "Trigger Scan" button to the agent table. It calls the POST endpoint and shows a toast notification "Scan queued".

### Feature 8: Scan Detail Report View

* **Repository:** `lyncis-ui` & `lyncis-backend`
* **Goal:** Allow users to dive deep into the results of a specific agent's latest scan, viewing both aggregated findings and raw data.
* **Bckend Tasks:**
  * Ensure `GET /api/v1/ui/agents/{agent_id}/scans/latest` is fully implemented. It must return the scan record, the associated scan_findings (array of warnings and suggestions), and the raw_data JSONB.
* **UI Tasks:**
  1. Add a "View Report" button to the actions column in the Agent list table (`/agents`).
  2. Create a new dynamic route: `/agents/:agentId/report`.
  3. Implement a data fetcher for this route calling the latest scan endpoint.
  4. **Layout Design:**
      * Top section: Header with Hostname, Scan Timestamp, and a large, colored Hardening Index score indicator.
      * Middle section: A tabbed interface or grid separating "Warnings" and "Suggestions". Display these findings in a clean list or table (Test ID, Description).
      * Bottom section: An expandable accordion or a read-only JSON viewer component displaying the raw_data for deep technical inspection.

### Feature 9: Dashboard Agent Hardening Overview

* **Repository:** `lyncis-backend` & `lyncis-ui`
* **Goal:** Provide a quick visual overview on the dashboard of all agents and their current security posture (Hardening Index).
* **Backend Tasks:**
  1. Modify `GET /api/v1/ui/agents`: Update the underlying GORM query to include the l`atest_hardening_index` and `latest_scan_at` for each agent. This requires a `LEFT JOIN` or a subquery on the `scans` table, ordering by `created_at DESC` and limiting to 1 per agent.
* **UI Tasks:**
  1. On the `/dashboard` route, add a new section below the KPI cards (e.g., "Agent Posture Overview").
  2. Display a compact list or a horizontal bar chart (using `recharts` or native Tailwind widths) plotting the `hostname` against their `latest_hardening_index`.
  3. Apply color-coding to the indices (e.g., Red for < 50, Yellow for 50-75, Green for > 75) following the Sci-Fi theme (`#ef4444`, `#eab308`, `#10b981` mixed with the dark surface colors).

### Feature 10: Global Critical Warnings View

* **Repository:** `lyncis-backend` & `lyncis-ui`
* **Goal:** Create an actionable to-do list for administrators by aggregating all critical warnings across the entire infrastructure into one view, accessible directly from the dashboard.
* **Backend Tasks:**
  1. **New Endpoint:** Create `GET /api/v1/ui/findings`.
  2. **Logic:** Support query parameters like `?severity=warning`. The query must join the `scan_findings`, `scans`, and `agents` tables to return a flat list containing: `finding_id`, `severity`, `test_id`, `description`, `agent_id`, `hostname`, and `scan_date`. Filter this to only include findings from the latest scan of each agent to avoid showing historical, already-fixed issues.
* **UI Tasks:**
  1. Convert the "Critical Warnings" KPI card on the `/dashboard` into a clickable link (`<Link to="/findings?severity=warning">`).
  2. Create a new route: `/findings`.
  3. Implement a data table fetching from the new backend endpoint.
  4. **Table Columns:** Hostname (clickable, linking to the agent's report), Test ID, Description, Severity.
  5. Add local filtering to the table (e.g., a search bar to filter by Description or Hostname).

#### Feature 11: Real-Time Agent Activity Status & Task Throttling

* **Repository:** `lyncis-backend` & `lyncis-ui`
* **Goal:** Visually indicate if an agent is currently executing a scan or has one queued, and prevent users from spamming the "Trigger Scan" button for busy agents.
* **Backend Tasks:**
  1. **Modify Response Model:** Update the agent response struct for GET /api/v1/ui/agents to include a new field: `activity_status` (string: `'idle'`, `'pending'`, `'scanning'`).
  2. **Update Query Logic:** In the `GET /api/v1/ui/agents` handler, execute a `LEFT JOIN` or subquery against the `tasks` table to check for active tasks for each agent.
      * If a task exists with `status='running'`, set `activity_status = 'scanning'`.
      * If a task exists with `status='pending'`, set `activity_status = 'pending'`.
      * Otherwise, set `activity_status = 'idle'`.
  3. **Backend Validation (Safety Net):** Update the `POST /api/v1/ui/agents/{agent_id}/scan` endpoint to reject the request (e.g., HTTP 409 Conflict) if the agent already has a task in `pending` or `running` state.
* **UI Tasks:**
  1. **Agent Table Update:** Add a new column or an icon next to the Agent's name in the `/agents` list representing the `activity_status`.
      * `'idle'`: Empty or a subtle checkmark.
      * `'pending'`: An hourglass icon or a pulsing "Queued" badge.
      * `'scanning'`: An animated spinner (using `lucide-react'`s `Loader2` with `animate-spin` class) and a "Scanning..." badge.
  2. **Button State:** Update the "Trigger Scan" button logic in the table.
      * Set `disabled={agent.activity_status !== 'idle'}`.
      * Apply styling changes (e.g., lower opacity, cursor-not-allowed) when disabled.
  3. **Tooltip/Feedback:** Add a tooltip over the disabled button that explains: *"A scan is already scheduled or in progress for this agent."*
