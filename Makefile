.PHONY: lint docker-build lambda-test tf-plan bootstrap simulate-attack

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
