setup:
	./scripts/setup.sh

start:
	docker-compose up -d

stop:
	docker-compose down

restart: stop start

reset:
	./scripts/reset.sh

health:
	./scripts/health_check.sh

logs:
	docker-compose logs -f

logs-redis:
	docker-compose logs -f redis

logs-db:
	docker-compose logs -f database

ps:
	docker-compose ps

shell-redis:
	docker exec -it securisphere-redis redis-cli

shell-db:
	docker exec -it securisphere-db psql -U securisphere_user -d securisphere_db

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf logs/*.log

help:
	@echo "Available commands:"
	@echo "  setup       - Run initial setup script"
	@echo "  start       - Start services with docker-compose"
	@echo "  stop        - Stop services"
	@echo "  restart     - Restart services"
	@echo "  reset       - Reset environment (remove containers and volumes)"
	@echo "  health      - Run health check script"
	@echo "  logs        - View all logs"
	@echo "  logs-redis  - View redis logs"
	@echo "  logs-db     - View database logs"
	@echo "  ps          - List running containers"
	@echo "  shell-redis - open redis-cli"
	@echo "  shell-db    - open psql shell"
	@echo "  clean       - Remove temporary files"

build:
	docker-compose build

build-api:
	docker-compose build api-server

build-auth:
	docker-compose build auth-service

test-api:
	@echo "--- Health Check ---"
	@curl -s http://localhost:5000/api/health | python -m json.tool
	@echo "--- List Products ---"
	@curl -s http://localhost:5000/api/products | python -m json.tool
	@echo "--- Search Products ---"
	@curl -s "http://localhost:5000/api/products/search?q=laptop" | python -m json.tool
	@echo "--- SQL Injection Test ---"
	@curl -s "http://localhost:5000/api/products/search?q=' OR '1'='1" | python -m json.tool
	@echo "--- Path Traversal Test ---"
	@curl -s "http://localhost:5000/api/files?name=../../../etc/passwd" | python -m json.tool
	@echo "--- Admin Config ---"
	@curl -s http://localhost:5000/api/admin/config | python -m json.tool

test-auth:
	@echo "--- Auth Status ---"
	@curl -s http://localhost:5001/auth/status | python -m json.tool
	@echo "--- Successful Login ---"
	@curl -s -X POST http://localhost:5001/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}' | python -m json.tool
	@echo "--- Failed Login ---"
	@curl -s -X POST http://localhost:5001/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"wrongpass"}' | python -m json.tool
	@echo "--- Reset All ---"
	@curl -s -X POST http://localhost:5001/auth/reset-all | python -m json.tool

test-phase2:
	python -m pytest tests/test_phase2.py -v

shell-api:
	docker exec -it securisphere-api /bin/bash

shell-auth:
	docker exec -it securisphere-auth /bin/bash

logs-api:
	docker-compose logs -f api-server

logs-auth:
	docker-compose logs -f auth-service

# Phase 3 Targets
build-monitors:
	docker-compose build network-monitor api-monitor auth-monitor

start-monitors:
	docker-compose up -d network-monitor api-monitor auth-monitor

stop-monitors:
	docker-compose stop network-monitor api-monitor auth-monitor

test-monitors:
	bash scripts/test_monitors.sh

test-phase3:
	python -m pytest tests/test_phase3.py -v

logs-netmon:
	docker-compose logs -f network-monitor

logs-apimon:
	docker-compose logs -f api-monitor

logs-authmon:
	docker-compose logs -f auth-monitor

monitor-events:
	docker exec -it securisphere-redis redis-cli SUBSCRIBE security_events

# Phase 4 Targets
build-backend:
	docker-compose build backend

start-backend:
	docker-compose up -d backend

stop-backend:
	docker-compose stop backend

logs-backend:
	docker-compose logs -f backend

test-backend:
	bash scripts/test_backend.sh

test-phase4:
	python -m pytest tests/test_phase4.py -v

shell-backend:
	docker exec -it securisphere-backend /bin/bash

# Phase 5 Targets
build-frontend:
	docker-compose build dashboard

start-frontend:
	docker-compose up -d dashboard

stop-frontend:
	docker-compose stop dashboard

logs-frontend:
	docker-compose logs -f dashboard

open-dashboard:
	echo "Opening http://localhost:3000" && (xdg-open http://localhost:3000 2>/dev/null || open http://localhost:3000 2>/dev/null || start http://localhost:3000 2>/dev/null)

# Phase 6 Targets
build-engine:
	docker-compose build correlation-engine

start-engine:
	docker-compose up -d correlation-engine

stop-engine:
	docker-compose stop correlation-engine

logs-engine:
	docker-compose logs -f correlation-engine

test-correlation:
	bash scripts/test_correlation.sh

engine-stats:
	curl -s http://localhost:5070/engine/stats | python3 -m json.tool || echo "Failed to fetch stats"

# Phase 7: Attack Simulator
build-simulator:
	docker-compose build attack-simulator

attack-killchain:
	docker-compose run --rm attack-simulator full_kill_chain

attack-api:
	docker-compose run --rm attack-simulator api_abuse

attack-creds:
	docker-compose run --rm attack-simulator credential_attack

attack-benign:
	docker-compose run --rm attack-simulator benign

attack-stealth:
	docker-compose run --rm attack-simulator stealth

attack-all:
	docker-compose run --rm attack-simulator all

demo:
	docker-compose run --rm attack-simulator full_kill_chain --delay demo

run-demo:
	bash scripts/run_demo.sh
