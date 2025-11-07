.PHONY: help deps lint test format precommit baseline

help:
	@echo "Available targets:"
	@echo "  make deps        - install dev dependencies"
	@echo "  make lint        - run ruff / black"
	@echo "  make test        - run pytest"
	@echo "  make precommit   - run pre-commit hooks"
	@echo "  make baseline    - regenerate detect-secrets baseline (careful!)"

deps:
	python -m pip install --upgrade pip
	pip install -r requirements.txt

lint:
	ruff check .
	black --check .

format:
	black .
	ruff format .

test:
	pytest -q

precommit:
	pre-commit run --all-files

baseline:
	# regenerate baseline only after auditing results
	detect-secrets scan > .secrets.baseline
