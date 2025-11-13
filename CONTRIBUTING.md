# Contributing to keycloak-auth-utils

Thank you for contributing to keycloak-auth-utils! This guide will help you set up your development environment and follow our contribution workflow.

## Development Setup

### Quick Start (Recommended)

```bash
# 1. Clone and enter directory
git clone https://github.com/ottuco/keycloak-auth-utils.git
cd keycloak-auth-utils

# 2. Create virtual environment
make venv

# 3. Activate virtual environment
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
# Or use: source .venv-activate.sh

# 4. Install all dependencies
make install-dev

# 5. You're ready! Run tests
make test-django
```

### What `make install-dev` Does

- Installs the package in editable mode
- Installs all development dependencies (black, flake8, isort, pre-commit, tox, pytest, etc.)
- Sets up pre-commit hooks
- Installs Django and FastAPI test dependencies

**Note:** All `make` commands automatically use `.venv` if it exists!

## Development Workflow

### Running Tests

**Run all tests (recommended before submitting PR):**

```bash
make test
# Or: tox
```

**Run Django tests only:**

```bash
make test-django
# Or: pytest tests/test_rest_framework/
```

**Run FastAPI tests only:**

```bash
make test-fastapi
# Or: pytest tests/test_fastapi/
```

**Run specific test file:**

```bash
pytest tests/test_rest_framework/tests/test_views.py -v
```

### Code Quality

**Format code (black + isort):**

```bash
make format
```

**Run linting:**

```bash
make lint
```

**Run pre-commit hooks manually:**

```bash
make pre-commit
# Or: pre-commit run --all-files
```

**Pre-commit hooks will automatically run on every commit and check:**

- Trailing whitespace
- End of file fixes
- Debug statements
- TOML file syntax
- Private key detection
- Code formatting (autopep8, black, isort)
- Code style (pyupgrade for Python 3.6+)

## Code Style Guidelines

This project follows:

- **PEP 8** for Python code style
- **Black** for code formatting (line length: 88)
- **isort** for import sorting (black-compatible profile)
- **Type hints** where appropriate
- **Docstrings** for all public classes and functions

## Testing Guidelines

- Write tests for all new features and bug fixes
- Ensure all tests pass before submitting a PR
- Aim for high test coverage
- Use pytest for all tests
- Follow existing test patterns in the codebase

## Security

If you discover a security vulnerability, please report it privately to the maintainers rather than opening a public issue.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`make test && make lint`)
5. Commit your changes (pre-commit hooks will run automatically)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### PR Guidelines

- Write a clear description of the changes
- Reference any related issues
- Ensure all tests pass
- Update documentation if needed
- Keep changes focused and atomic

## Project Structure

```txt
keycloak-auth-utils/
├── src/keycloak_utils/          # Main package source code
│   ├── authentication/          # Authentication modules
│   ├── contrib/                 # Framework integrations (Django, etc.)
│   ├── consumer/                # Event consumer modules
│   ├── manager/                 # Key management
│   └── sync/                    # Synchronization utilities
├── tests/                       # Test suite
│   ├── test_rest_framework/     # Django/DRF tests
│   └── test_fastapi/            # FastAPI tests
├── pyproject.toml               # Project metadata and dependencies
├── tox.ini                      # Tox configuration
├── .pre-commit-config.yaml      # Pre-commit hooks configuration
└── Makefile                     # Development commands
```

## Useful Commands

```bash
# View all available make commands
make help

# Install package for development
make install-dev

# Run all tests across Python versions
make test

# Run only Django tests
make test-django

# Format code
make format

# Run linting
make lint

# Clean build artifacts
make clean
```

## Questions?

If you have questions or need help, please:

1. Check existing issues
2. Open a new issue with your question
3. Reach out to the maintainers

Thank you for contributing! 🎉
