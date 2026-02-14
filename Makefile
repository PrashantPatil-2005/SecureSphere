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
