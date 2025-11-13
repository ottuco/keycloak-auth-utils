.PHONY: help install install-dev test test-django test-fastapi lint format clean pre-commit venv

# Use .venv if it exists, otherwise fall back to system python
PYTHON := $(shell [ -d .venv ] && echo .venv/bin/python || echo python3)
PIP := $(shell [ -d .venv ] && echo .venv/bin/pip || echo pip)
PYTEST := $(shell [ -d .venv ] && echo .venv/bin/pytest || echo pytest)
FLAKE8 := $(shell [ -d .venv ] && echo .venv/bin/flake8 || echo flake8)
BLACK := $(shell [ -d .venv ] && echo .venv/bin/black || echo black)
ISORT := $(shell [ -d .venv ] && echo .venv/bin/isort || echo isort)
PRECOMMIT := $(shell [ -d .venv ] && echo .venv/bin/pre-commit || echo pre-commit)
TOX := $(shell [ -d .venv ] && echo .venv/bin/tox || echo tox)

help:
	@echo "Available commands:"
	@echo "  make venv           - Create virtual environment (.venv)"
	@echo "  make install        - Install package in editable mode"
	@echo "  make install-dev    - Install package with dev dependencies"
	@echo "  make test           - Run all tests with tox"
	@echo "  make test-django    - Run Django tests only"
	@echo "  make test-fastapi   - Run FastAPI tests only"
	@echo "  make lint           - Run linting (flake8)"
	@echo "  make format         - Run code formatters (black, isort)"
	@echo "  make pre-commit     - Run pre-commit hooks on all files"
	@echo "  make clean          - Remove build artifacts"

venv:
	python3 -m venv .venv
	@echo "✅ Virtual environment created. Activate with: source .venv/bin/activate"
	@echo "Then run: make install-dev"

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev]"
	$(PIP) install tox pytest pytest-django
	$(PRECOMMIT) install
	@echo "✅ Development environment ready!"

test:
	$(PIP) install -e ".[tox]"
	$(TOX)

test-django:
	PYTHONPATH=. $(PYTEST) tests/test_rest_framework/ -v

test-fastapi:
	PYTHONPATH=. $(PYTEST) tests/test_fastapi/ -v

lint:
	$(FLAKE8) src/ tests/

format:
	$(BLACK) src/ tests/
	$(ISORT) src/ tests/

pre-commit:
	$(PRECOMMIT) run --all-files

clean:
	rm -rf build/ dist/ *.egg-info .tox/ .pytest_cache/ .eggs/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
