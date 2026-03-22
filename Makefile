.PHONY: setup down logs test clean keys migrate help

.DEFAULT_GOAL := help

help: ## Show available commands
	@echo.
	@echo   PasetoAuthService — PASETO v4 Auth Service
	@echo.
	@echo   make setup    Build and start everything
	@echo   make down     Stop all services
	@echo   make logs     Tail service logs
	@echo   make test     Run test suite
	@echo   make clean    Nuke containers, volumes, .env
	@echo   make keys     Generate fresh PASETO keys
	@echo   make migrate  Run database migrations
	@echo.

setup: ## Build and start everything (plug-and-play)
	@if not exist .env copy .env.example .env >nul
	docker compose up --build -d
	@echo.
	@echo   PasetoAuthService is running
	@echo   API:  http://localhost:8420
	@echo   Docs: http://localhost:8420/docs
	@echo.

down: ## Stop all services
	docker compose down

logs: ## Tail application logs
	docker compose logs -f app

test: ## Run test suite inside container
	docker compose exec app pytest -v

clean: ## Remove containers, volumes, and .env
	docker compose down -v --remove-orphans
	@if exist .env del .env

keys: ## Generate new PASETO keys
	docker compose exec app python scripts/generate_keys.py

migrate: ## Run Alembic migrations
	docker compose exec app alembic upgrade head
