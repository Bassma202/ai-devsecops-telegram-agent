.PHONY: doctor setup test security opa-test demo up down clean

UV := $(HOME)/.local/bin/uv
PYTHON := .venv/bin/python

doctor:
	@command -v $(UV) >/dev/null || (echo "Missing uv" && exit 1)
	@$(UV) --version
	@docker --version 2>/dev/null || echo "Docker optional for local unit tests"

setup:
	$(UV) venv --python 3.12
	$(UV) pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -v

security:
	$(PYTHON) -m ruff check src app bot.py tests --select E9,F63,F7,F82
	$(PYTHON) -m bandit -r src app bot.py --severity-level high

opa-test:
	docker run --rm -v "$(PWD)/policies:/policies:ro" openpolicyagent/opa:1.1.0-static test /policies -v

demo:
	$(PYTHON) scripts/run_forge_demo.py

up:
	$(PYTHON) -m uvicorn forge.web:app --host 127.0.0.1 --port 8006

down:
	docker compose down --remove-orphans || true

clean:
	rm -rf data/*.db data/active_release.json .pytest_cache
