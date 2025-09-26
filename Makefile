.PHONY: help install run test lint fmt migrate up down seed clean

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
