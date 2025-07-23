# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an ACME DNS challenge service that provides a registration management layer on top of the official acme-dns service. It consists of multiple Docker services orchestrated with Docker Compose and Traefik as a reverse proxy.

## Architecture

The system has four main components:

1. **acme-dns** - The core DNS server (joohoi/acme-dns Docker image)
2. **registration-api** - Python Flask service for API key management and registration tracking (`registration-service/`)
3. **admin-ui** - Web interface for managing API keys and viewing statistics (`admin-ui/index.html`)
4. **traefik** - Reverse proxy handling SSL termination and routing

All services communicate through Docker networks with Traefik handling external access and SSL certificates via Let's Encrypt.

## Development Commands

### Start/Stop Services
```bash
# Start all services
docker compose up -d

# Stop all services
docker compose down

# View logs
docker compose logs -f [service-name]

# Restart specific service
docker compose restart [service-name]
```

### Service Management
```bash
# Enable systemd service (after deployment)
systemctl enable --now acmedns

# Check service status
systemctl status acmedns
```

### API Key Management
```bash
# Create new API key
./manage-keys.sh create

# List all API keys
./manage-keys.sh list

# Revoke API key
./manage-keys.sh revoke

# View service statistics
./manage-keys.sh stats

# View recent registrations
./manage-keys.sh regs

# Test service health
./manage-keys.sh test
```

### Development Setup
```bash
# Quick deployment setup
./quick-deploy.sh

# Build registration service image
docker compose build registration-api

# Access Python service for debugging
docker compose exec registration-api /bin/bash
```

## Key Configuration Files

- `docker-compose.yml` - Main service orchestration
- `acme-dns/config.cfg` - ACME DNS server configuration
- `traefik/traefik.yml` - Reverse proxy configuration
- `registration-service/registration-service.py` - Main API service
- `admin-ui/index.html` - Web management interface

## Important Environment Variables

- `MASTER_API_KEY` - Required for admin operations
- `PUBLIC_IP` - Server public IP address
- `DASHBOARD_AUTH` - Traefik dashboard authentication
- `ADMIN_AUTH` - Admin UI authentication

## API Endpoints

### Public Endpoints (require X-API-Key header)
- `POST /register` - Register new domain
- `GET /health` - Service health check
- `GET /info` - API key information

### Admin Endpoints (require Authorization: Bearer header with master key)
- `POST /admin/keys` - Create API key
- `GET /admin/keys` - List API keys
- `DELETE /admin/keys/{key_id}` - Revoke API key
- `GET /admin/registrations` - List registrations
- `GET /admin/stats` - Service statistics

## Database Schema

The registration service uses SQLite with two main tables:
- `api_keys` - Stores API key metadata and usage statistics
- `registrations` - Tracks domain registrations per API key

## Security Notes

- Master API key is stored in `master.key` and must be kept secure
- Dashboard credentials are auto-generated during deployment
- All external traffic goes through Traefik with SSL termination
- Registration service runs as non-root user in container