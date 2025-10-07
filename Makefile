.PHONY: help install run test lint fmt migrate up down seed clean elk-install elk-up elk-down elk-migrate elk-setup elk-dashboard

# Variables
PYTHON := poetry run python
UVICORN := poetry run uvicorn
CELERY := poetry run celery
ALEMBIC := poetry run alembic
PYTEST := poetry run pytest

help: ## Show help message
	@echo "Phisherman Development Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	poetry install
	poetry run pre-commit install

run: ## Run the API server
	$(UVICORN) phisherman.api.main:app --host 0.0.0.0 --port 8000 --reload

worker: ## Run Celery worker
	$(CELERY) -A phisherman.tasks.celery_app worker --loglevel=info

beat: ## Run Celery beat scheduler
	$(CELERY) -A phisherman.tasks.celery_app beat --loglevel=info

test: ## Run tests
	$(PYTEST) -v --cov=phisherman --cov-report=html

test-fast: ## Run tests without coverage
	$(PYTEST) -v -x

lint: ## Run linting
	poetry run ruff check .
	poetry run mypy phisherman

lint-fix: ## Fix linting issues
	poetry run ruff check . --fix

fmt: ## Format code
	poetry run black .
	poetry run ruff check . --fix

migrate: ## Run database migrations
	$(ALEMBIC) upgrade head

migrate-auto: ## Generate automatic migration
	$(ALEMBIC) revision --autogenerate -m "Auto migration"

migrate-rollback: ## Rollback last migration
	$(ALEMBIC) downgrade -1

up: ## Start all services with docker-compose
	docker-compose up -d

down: ## Stop all services
	docker-compose down

logs: ## Show docker-compose logs
	docker-compose logs -f

seed: ## Seed database with test data
	$(PYTHON) scripts/seed_victim_data.py

seed-basic: ## Seed basic URL analysis data (if available)
	$(PYTHON) -c "from phisherman.scripts.seed_db import main; main()" || echo "Basic seed data not available"

clean: ## Clean up temporary files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/

generate-env: ## Generate secure .env file from template
	python3 scripts/generate-env.py

dev-setup: ## Complete development setup
	@echo "Setting up Phisherman development environment..."
	make install
	make generate-env
	@echo "✅ Development environment ready!"
	@echo "📝 Edit .env file if you need to customize configuration"
	@echo "🚀 Run: make migrate && make up to start services"

check: ## Run all checks (lint, type check, test)
	make lint
	make test

build: ## Build Docker image
	docker build -t phisherman:latest .

docker-run: ## Run with Docker (single container)
	docker run -p 8000:8000 --env-file .env phisherman:latest

# ========== ELK Stack Commands ==========

elk-install: ## Install ELK dependencies
	pip install -r requirements-elk.txt
	@echo "✅ ELK dependencies installed"

elk-up: ## Start ELK stack (Elasticsearch + Kibana)
	@echo "🚀 Starting ELK stack..."
	docker-compose -f docker-compose.elk.yml up -d
	@echo "⏳ Waiting for services to be ready..."
	@sleep 30
	@echo "✅ ELK stack started!"
	@echo "🔍 Elasticsearch: http://localhost:9200"
	@echo "📊 Kibana: http://localhost:5601"

elk-down: ## Stop ELK stack
	docker-compose -f docker-compose.elk.yml down
	@echo "🛑 ELK stack stopped"

elk-logs: ## Show ELK stack logs
	docker-compose -f docker-compose.elk.yml logs -f

elk-migrate: ## Migrate vehicle data to Elasticsearch (full migration)
	@echo "📦 Starting full migration of vehicle data..."
	python3 migrate_vehicles_to_elasticsearch.py
	@echo "✅ Migration completed!"

elk-migrate-test: ## Migrate sample data to Elasticsearch (1000 records for testing)
	@echo "🧪 Migrating sample data (1000 records)..."
	python3 migrate_vehicles_to_elasticsearch.py --limit 1000
	@echo "✅ Test migration completed!"

elk-dashboard: ## Setup Kibana dashboards automatically
	@echo "📈 Setting up Kibana dashboards..."
	python3 setup_kibana_dashboards.py
	@echo "✅ Dashboards configured!"
	@echo "🔗 Access dashboard: http://localhost:5601/app/kibana#/dashboard/vehicles-main-dashboard"

elk-setup: ## Complete ELK setup (install + start + migrate sample + dashboard)
	@echo "🚀 Complete ELK setup starting..."
	make elk-install
	make elk-up
	@echo "⏳ Waiting for ELK to be fully ready..."
	@sleep 60
	make elk-migrate-test
	make elk-dashboard
	@echo ""
	@echo "🎉 ¡ELK Stack configurado completamente!"
	@echo ""
	@echo "📊 Kibana Dashboard: http://localhost:5601/app/kibana#/dashboard/vehicles-main-dashboard"
	@echo "🔍 Elasticsearch: http://localhost:9200"
	@echo "📈 Discover data: http://localhost:5601/app/kibana#/discover"
	@echo ""
	@echo "Comandos útiles:"
	@echo "  make elk-migrate        # Migrar todos los datos"
	@echo "  make elk-migrate-test   # Migrar solo 1000 registros de prueba"
	@echo "  make elk-logs          # Ver logs del stack"
	@echo "  make elk-down          # Parar el stack"

elk-status: ## Check ELK stack status
	@echo "📊 ELK Stack Status:"
	@echo ""
	@echo "🔍 Elasticsearch:"
	@curl -s http://localhost:9200/_cluster/health?pretty 2>/dev/null || echo "   ❌ Not available"
	@echo ""
	@echo "📊 Kibana:"
	@curl -s http://localhost:5601/api/status 2>/dev/null | grep -q "available" && echo "   ✅ Available" || echo "   ❌ Not available"
	@echo ""
	@echo "📈 Vehicle Index:"
	@curl -s http://localhost:9200/vehicles/_count?pretty 2>/dev/null || echo "   ❌ Index not found"
