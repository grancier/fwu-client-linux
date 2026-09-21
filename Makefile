PYTHON ?= python3
VENV   ?= .venv

.PHONY: help venv build install install-dev test lint clean run

help:
	@echo "make venv         create $(VENV)"
	@echo "make build        build the wheel and sdist"
	@echo "make install      install into the active environment"
	@echo "make install-dev  install with test and lint extras"
	@echo "make test         run the unit tests (no hardware required)"
	@echo "make lint         run ruff"
	@echo "make run          run fwu-info against the local ME (needs root)"
	@echo "make clean        remove build artefacts"

venv:
	$(PYTHON) -m venv $(VENV)
	@echo "activate with: . $(VENV)/bin/activate"

build:
	$(PYTHON) -m pip install --quiet build
	$(PYTHON) -m build

install:
	$(PYTHON) -m pip install .

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check fwu tests research

run:
	sudo $(PYTHON) -m fwu.cli

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
