.PHONY: help install install-dev test validate lint format clean docker-up docker-down docker-logs

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install development dependencies
	pip install -r requirements.txt
	pip install -r requirements-dev.txt
	pre-commit install

test: ## Run test suite
	@echo "Running unit tests..."
	python3 tests/test_core_functionality.py

validate: ## Run system validation
	@echo "Running system validation..."
	python3 tests/validate_system.py

lint: ## Run linting checks
	@echo "Running flake8..."
	flake8 phase_*/ tests/ --count --show-source --statistics
	@echo "Running pylint..."
	pylint phase_*/ tests/ --exit-zero

format: ## Format code with black
	@echo "Formatting Python code..."
	black phase_*/ tests/ --line-length 100

format-check: ## Check code formatting without making changes
	@echo "Checking code formatting..."
	black --check phase_*/ tests/ --line-length 100

type-check: ## Run type checking with mypy
	@echo "Running mypy type checks..."
	mypy phase_*/ tests/ --ignore-missing-imports

security-scan: ## Run security scans
	@echo "Running bandit security scan..."
	bandit -r phase_*/ -f json -o security-report.json
	@echo "Checking dependencies for vulnerabilities..."
	safety check --json

clean: ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	rm -rf .pytest_cache .mypy_cache htmlcov *.egg-info
	@echo "Cleaned up generated files"

docker-up: ## Start all Docker services
	@echo "Starting AIRDFP services..."
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	sleep 30
	@echo "Services started. Access TheHive at http://localhost:9000"

docker-down: ## Stop all Docker services
	@echo "Stopping AIRDFP services..."
	docker-compose down

docker-logs: ## Show Docker service logs
	docker-compose logs -f

docker-restart: ## Restart all Docker services
	$(MAKE) docker-down
	$(MAKE) docker-up

all: install-dev validate test lint ## Run full setup and validation

quick-start: ## Quick start deployment
	@echo "🚀 AIRDFP Quick Start"
	@echo "===================="
	@echo ""
	@echo "Step 1: Installing dependencies..."
	$(MAKE) install
	@echo ""
	@echo "Step 2: Starting Docker services..."
	$(MAKE) docker-up
	@echo ""
	@echo "Step 3: Running validation..."
	sleep 10
	$(MAKE) validate
	@echo ""
	@echo "✅ AIRDFP is ready!"
	@echo ""
	@echo "Next steps:"
	@echo "  - Access TheHive UI: http://localhost:9000"
	@echo "  - Default credentials: admin@thehive.local / secret"
	@echo "  - Run demo: python3 scripts/demo_incident.py"
