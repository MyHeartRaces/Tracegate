.PHONY: install lint test run-api run-agent run-dispatcher run-bot init-db

install:
	pip install -e '.[dev]' -c requirements.lock

lint:
	ruff check src tests

test:
	pytest -q

run-api:
	tracegate-api

run-agent:
	tracegate-agent

run-dispatcher:
	tracegate-dispatcher

run-bot:
	tracegate-bot

init-db:
	tracegate-init-db
