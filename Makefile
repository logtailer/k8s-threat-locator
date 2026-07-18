.PHONY: lint docker-build lambda-test tf-plan bootstrap simulate-attack local-bootstrap local-responder local-simulate-attack local-down

# IMAGE_TAG controls which ECR tag bootstrap deploys (default: latest)
IMAGE_TAG ?= latest

lint:
	ruff check lambda/handler.py lambda/triage.py
	ruff format --check lambda/handler.py lambda/triage.py
	yamllint -d relaxed falco/values.yaml falco/rules/custom-rules.yaml k8s/
	@# Guard: rules live only in falco/rules/custom-rules.yaml (injected via --set-file).
	@if grep -qE '^\s*- rule:' falco/values.yaml; then \
		echo "ERROR: falco/values.yaml must not contain Falco rules — edit falco/rules/custom-rules.yaml"; \
		exit 1; \
	fi

docker-build:
	docker build --platform linux/amd64 -t k8s-threat-locator-app:local app/

lambda-test:
	cd lambda && python -m pytest tests/ -v --tb=short

tf-plan:
	terraform -chdir=terraform plan -out=tfplan

# One-shot setup after terraform apply.
# Reads all values from terraform output — no manual copy-paste required.
# Accepts the same flags as scripts/bootstrap.sh, e.g.:
#   make bootstrap IMAGE_TAG=v1.0.0
bootstrap:
	@scripts/bootstrap.sh --image-tag "$(IMAGE_TAG)"

simulate-attack:
	@scripts/simulate-attack.sh

LOCAL_VENV ?= .venv-local

local-bootstrap:
	@scripts/local-bootstrap.sh

# Runs the handler in a venv so boto3/kubernetes are present (the system
# python may lack them). ARGS lets you pass flags, e.g. ARGS=--once.
local-responder:
	@test -x $(LOCAL_VENV)/bin/python || python3 -m venv $(LOCAL_VENV)
	@$(LOCAL_VENV)/bin/pip install -q -r lambda/requirements.txt
	@$(LOCAL_VENV)/bin/python scripts/local-responder.py $(ARGS)

local-simulate-attack:
	@scripts/local-simulate-attack.sh

local-down:
	@kind delete cluster --name "$${KIND_CLUSTER:-ktl-local}" || true
	@docker compose -f docker-compose.localstack.yml down -v
	@rm -f .env.localtest
	@rm -rf $(LOCAL_VENV)
