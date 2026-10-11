.PHONY: setup run test lint seed demo verify docker-up docker-down clean help bootstrap

PYTHON ?= python3
PIP ?= pip3
VENV ?= .venv
BIN := $(VENV)/bin
export PYTHONPATH := .

help:
	@echo "AgentWarden Makefile targets:"
	@echo "  make setup      - create venv and install dependencies"
	@echo "  make run        - start the FastAPI server"
	@echo "  make test       - run pytest"
	@echo "  make lint       - run ruff"
	@echo "  make bootstrap  - create demo users only"
	@echo "  make seed       - seed full demo data"
	@echo "  make demo       - run terminal demo agent"
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

bootstrap:
	$(PYTHON) scripts/bootstrap_admin.py

seed:
	$(PYTHON) scripts/seed.py

demo:
	$(PYTHON) scripts/demo_agent.py

verify:
	$(PYTHON) scripts/smoke_test.py

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache .coverage htmlcov
	rm -f agentwarden.db *.db .tamper_backup.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
