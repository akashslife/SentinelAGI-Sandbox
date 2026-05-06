# ============================================
# SentinelAGI Sandbox - Makefile
# ============================================

.PHONY: help install test lint format run docker-build docker-up docker-down clean quickstart

help:
	@echo "SentinelAGI Sandbox - Available commands:"
	@echo ""
	@echo "  make install       - Install dependencies"
	@echo "  make test          - Run test suite"
	@echo "  make test-cov      - Run tests with coverage"
	@echo "  make lint          - Run linter (ruff)"
	@echo "  make format        - Format code"
	@echo "  make typecheck     - Run type checker (mypy)"
	@echo "  make run           - Run API server locally"
	@echo "  make quickstart    - Run quick demo"
	@echo "  make docker-build  - Build Docker images"
	@echo "  make docker-up     - Start with Docker Compose"
	@echo "  make docker-down   - Stop Docker Compose"
	@echo "  make clean         - Clean up containers and cache"
	@echo ""

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --asyncio-mode=auto

test-cov:
	pytest tests/ -v --cov=sentinelagi --cov-report=html --cov-report=term

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/sentinelagi/ --ignore-missing-imports

run:
	python -m sentinelagi.main server --host 0.0.0.0 --port 8000 --reload

quickstart:
	python -m sentinelagi.main quickstart

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

clean:
	docker-compose down -v
	docker system prune -f
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
