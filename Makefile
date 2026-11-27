PYTHON ?= python
VENV_DIR ?= .venv
KIND_CLUSTER ?= sre-incident-commander

.DEFAULT_GOAL := help

.PHONY: help venv install test lint compose-up compose-down build kind-create kind-load kind-deploy kind-delete config-check demo

help:
	@echo "SRE Incident Commander"
	@echo ""
	@echo "Targets:"
	@echo "  venv         Create a local Python virtual environment"
	@echo "  install      Install development dependencies"
	@echo "  test         Run pytest"
	@echo "  lint         Run Ruff lint and formatting checks"
	@echo "  config-check Validate Compose and render Kubernetes manifests"
	@echo "  compose-up   Build and start the full Docker Compose stack"
	@echo "  compose-down Stop the Docker Compose stack"
	@echo "  build        Build all application images"
	@echo "  kind-create  Create a local kind cluster"
	@echo "  kind-load    Load application images into kind"
	@echo "  kind-deploy  Apply Kubernetes manifests"
	@echo "  kind-delete  Delete the kind cluster"
	@echo "  demo         Trigger a failure and generate an incident report"

venv:
	$(PYTHON) -m venv $(VENV_DIR)

install:
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

config-check:
	docker compose config --quiet
	kubectl kustomize .

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

build:
	docker compose build

kind-create:
	kind create cluster --name $(KIND_CLUSTER) --wait 120s

kind-load: build
	kind load docker-image sre-orders:local sre-payments:local sre-inventory:local sre-incident-commander:local --name $(KIND_CLUSTER)

kind-deploy:
	kubectl apply -k .
	kubectl rollout status deployment/orders -n sre --timeout=180s
	kubectl rollout status deployment/payments -n sre --timeout=180s
	kubectl rollout status deployment/inventory -n sre --timeout=180s
	kubectl rollout status deployment/incident-commander -n sre --timeout=180s

kind-delete:
	kind delete cluster --name $(KIND_CLUSTER)

demo:
	$(PYTHON) scripts/demo.py
