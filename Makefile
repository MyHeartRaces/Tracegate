.PHONY: install lint test helm-check privacy-check release-check release-artifacts run-api run-agent run-dispatcher run-bot init-db

install:
	pip install -e '.[dev]' -c requirements.lock

lint:
	ruff check src tests deploy

test:
	pytest -q

helm-check:
	helm lint ./deploy/k3s/tracegate
	helm template tracegate ./deploy/k3s/tracegate >/tmp/tracegate-rendered.yaml

privacy-check:
	python3 scripts/check_public_release.py

release-check: lint test helm-check privacy-check
	git diff --check

release-artifacts: release-check
	scripts/build_release_artifacts.sh 3.0.0

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
