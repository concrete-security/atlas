PYTEST_BASE_CMD = uv run pytest -v
PYTEST_DEBUG_PREFIX = DEBUG_ATLS=1
PYTEST_LOG_SUFFIX = -o log_cli=true
PYTEST_COV_OPTIONS = --cov=atlas --cov-report=term-missing --cov-fail-under=95

develop:
	uv run maturin develop

test:
ifdef SHOW_LOGS
	$(PYTEST_DEBUG_PREFIX) $(PYTEST_BASE_CMD) $(PYTEST_LOG_SUFFIX)
else
	$(PYTEST_BASE_CMD)
endif

test-coverage:
ifdef SHOW_LOGS
	$(PYTEST_DEBUG_PREFIX) $(PYTEST_BASE_CMD) $(PYTEST_COV_OPTIONS) $(PYTEST_LOG_SUFFIX)
else
	$(PYTEST_BASE_CMD) $(PYTEST_COV_OPTIONS)
endif

format:
	uv run ruff format

check-format:
	uv run ruff format --check

lint:
	uv run ruff check --fix

check-lint:
	uv run ruff check

qa-all-fix: format lint

qa-all: check-format check-lint

.PHONY: develop test test-coverage format check-format lint check-lint qa-all-fix qa-all
