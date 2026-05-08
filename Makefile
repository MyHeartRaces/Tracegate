.PHONY: install lint test helm-check release-check build-naiveproxy-caddy run-api run-agent run-dispatcher run-bot init-db

install:
	pip install -e '.[dev]' -c requirements.lock

lint:
	ruff check src tests

test:
	pytest -q

helm-check:
	helm lint ./deploy/k3s/tracegate
	helm template tracegate ./deploy/k3s/tracegate >/tmp/tracegate-rendered.yaml

release-check: lint test helm-check
	git diff --check

build-naiveproxy-caddy:
	docker build \
		-f deploy/images/naiveproxy-caddy/Dockerfile \
		--build-arg VCS_REF="$$(git rev-parse HEAD)" \
		-t tracegate-naiveproxy-caddy:local \
		.

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
