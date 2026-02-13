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
