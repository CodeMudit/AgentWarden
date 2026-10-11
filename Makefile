.PHONY: setup run test lint seed demo verify docker-up docker-down clean help

PYTHON ?= python3
PIP ?= pip3
VENV ?= .venv
BIN := $(VENV)/bin

help:
	@echo "AgentWarden Makefile targets:"
	@echo "  make setup      - create venv and install dependencies"
	@echo "  make run        - start the FastAPI server"
	@echo "  make test       - run pytest"
	@echo "  make lint       - run ruff"
	@echo "  make seed       - seed demo data (Phase 3)"
	@echo "  make demo       - run terminal demo agent (Phase 3)"
	@echo "  make verify     - end-to-end smoke test against running server"
	@echo "  make docker-up  - start app + Postgres via docker-compose"
	@echo "  make docker-down- stop docker-compose services"
	@echo "  make clean      - remove venv, caches, local db"

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	$(BIN)/pip install -e .
	@echo "Setup complete. Activate with: source $(VENV)/bin/activate"

run:
	$(BIN)/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	$(BIN)/pytest -v --tb=short

lint:
	$(BIN)/ruff check app tests scripts sdk
	$(BIN)/ruff format --check app tests scripts sdk

seed:
	@echo "Seed script arrives in Phase 3"
	@exit 1

demo:
	@echo "Demo agent arrives in Phase 3"
	@exit 1

verify:
	@echo "Smoke test arrives in Phase 3"
	@exit 1

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache .coverage htmlcov
	rm -f agentwarden.db *.db
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
