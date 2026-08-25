# PassiveShield AI — Infrastructure Skeleton & Verification Guide

## Overview
This directory contains the minimum reproducible Docker Compose infrastructure skeleton for PassiveShield AI's backend architecture.

### Managed Infrastructure Services:
1. **Redpanda (`passiveshield-redpanda`)**: Streaming event bus (Kafka API compatible) for decoupled telemetry, features, detection results, and alert streams.
2. **Redpanda Console (`passiveshield-redpanda-console`)**: Web dashboard for inspecting topics, schema registry, and streaming messages (Port 8080).
3. **Redis (`passiveshield-redis`)**: High-performance, in-memory bounded state store with TTL eviction for sliding-window traffic analytics (Port 6379).
4. **PostgreSQL (`passiveshield-postgres`)**: Primary relational persistence store for alert history, system metrics, and audit logs (Port 5432).
5. **API Service Placeholder (`passiveshield-api-placeholder`)**: Placeholder service demonstrating container networking and startup dependency ordering.

---

## Configuration & Environment Variables

All passwords, usernames, and ports are configurable via environment variables.

1. **Create local environment file**:
   ```bash
   cp .env.example .env
   ```
2. **Never commit `.env`**: `.env` is listed in `.gitignore` to prevent secret leaks.

---

## Service Lifecycle Commands

### 1. Validate Docker Compose Configuration
```bash
docker compose -f infra/docker-compose.yml --env-file .env.example config
```

### 2. Start Infrastructure Services
```bash
docker compose -f infra/docker-compose.yml --env-file .env.example up -d
```

### 3. Check Container Health Status
```bash
docker compose -f infra/docker-compose.yml ps
```

Expected healthy output:
- `passiveshield-redpanda` -> `healthy`
- `passiveshield-redis` -> `healthy`
- `passiveshield-postgres` -> `healthy`
- `passiveshield-api-placeholder` -> `healthy`

### 4. Inspect Service Logs
```bash
docker compose -f infra/docker-compose.yml logs -f
```

### 5. Stop Infrastructure Services
```bash
docker compose -f infra/docker-compose.yml down
```

To remove persistent volumes as well:
```bash
docker compose -f infra/docker-compose.yml down -v
```

---

## Health Verification Script
Run the automated verification script:
- **PowerShell (Windows)**:
  ```powershell
  .\scripts\verify_infra_config.ps1
  ```
- **Bash (Linux/macOS)**:
  ```bash
  ./scripts/verify_infra_config.sh
  ```
