.PHONY: install lint test host-check privacy-check release-check release-artifacts run-api run-agent run-dispatcher run-bot init-db

install:
	pip install -e '.[dev]' -c requirements.lock

lint:
	ruff check src tests deploy

test:
	pytest -q

host-check:
	python3 scripts/check_host_runtime.py

privacy-check:
	python3 scripts/check_public_release.py

release-check: lint test host-check privacy-check
	git diff --check

release-artifacts: release-check
	scripts/build_release_artifacts.sh $$(python3 -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')

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
