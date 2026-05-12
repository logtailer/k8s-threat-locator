.PHONY: lint docker-build lambda-build lambda-test tf-plan simulate-attack

lint:
	ruff check lambda/handler.py lambda/triage.py
	ruff format --check lambda/handler.py lambda/triage.py
	yamllint -d relaxed falco/values.yaml falco/rules/custom-rules.yaml k8s/

docker-build:
	docker build -t k8s-threat-locator-app:local app/

lambda-build:
	sam build --template lambda/template.yaml

lambda-test:
	cd lambda && python -m pytest tests/ -v --tb=short

tf-plan:
	terraform -chdir=terraform plan -out=tfplan

simulate-attack:
	@scripts/simulate-attack.sh
