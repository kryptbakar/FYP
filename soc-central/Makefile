# =====================================================================
# SOC Central — developer task runner.
# Linux/macOS: use `make <target>`.
# Windows (no make): use `pwsh scripts/dev.ps1 <target>` (same targets).
# =====================================================================

COMPOSE ?= docker compose
COMPOSE_TOOLS = $(COMPOSE) -f docker-compose.yml -f docker-compose.tools.yml

.DEFAULT_GOAL := help
.PHONY: help up down restart logs ps health seed test agent-run clone-refs env certs produce feeds-seed feeds-sync assess risk-train risk-score clone-tools sensors-test wazuh-pull scan-ingest

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example")

certs: ## Generate the dev mTLS PKI (idempotent; --force to regenerate)
	bash scripts/gen-certs.sh

up: env certs ## Build images and start the full MVP stack
	$(COMPOSE) up -d --build

N ?= 500
produce: ## Send N fake telemetry envelopes through the pipeline (default N=500)
	$(COMPOSE) run --rm fake-producer --count $(N)

agent-run: ## Build and launch the Go endpoint agent against the local stack
	$(COMPOSE) --profile agent up -d --build agent
	@echo "agent up. Follow logs:  $(COMPOSE) logs -f agent"

feeds-seed: ## Populate the local feed mirror from bundled fixtures (offline)
	$(COMPOSE) --profile feeds run --rm feed-sync --seed

feeds-sync: ## Mirror NVD/EPSS/KEV LIVE (the only internet-facing job)
	$(COMPOSE) --profile feeds run --rm feed-sync --feeds kev,epss,nvd

assess: ## Run a one-shot enrichment/assessment pass now
	$(COMPOSE) run --rm enrichment --once

risk-train: ## Train the XGBoost risk model (synthetic + analyst feedback)
	$(COMPOSE) --profile ml run --rm risk-engine train

risk-score: ## Score all findings: composite + ML risk + SHAP explanations
	$(COMPOSE) --profile ml run --rm risk-engine score

clone-tools: ## Clone the tool-integration reference repos into reference/ (study only)
	bash scripts/clone-references-tools.sh

sensors-test: ## (Phase B) run Suricata on the test pcap and ship alerts through the pipeline
	docker run --rm -v "$(CURDIR)/tools/sensors:/w" -w /w python:3.12-slim python make_test_pcap.py data/test.pcap
	$(COMPOSE_TOOLS) build sensor-bridge
	$(COMPOSE_TOOLS) run --rm --entrypoint suricata suricata -r /pcaps/test.pcap -l /var/log/suricata -S /var/lib/suricata/rules/local.rules -k none
	$(COMPOSE_TOOLS) run --rm sensor-bridge --once
	@echo "Suricata alerts shipped. Query: curl localhost:9200/telemetry-v1/_count -d '{\"query\":{\"term\":{\"source_tool.keyword\":\"suricata\"}}}'"

wazuh-pull: ## (Phase C) pull Wazuh FIM/SCA into the pipeline (FIXTURES=1 for offline)
	$(COMPOSE_TOOLS) build wazuh-bridge
	$(COMPOSE_TOOLS) run --rm wazuh-bridge $(if $(FIXTURES),--from-fixtures,)

scan-ingest: ## (Phase D) ingest Trivy + Nuclei scanner findings (bundled fixtures, offline)
	$(COMPOSE) build enrichment
	$(COMPOSE) run --rm enrichment --scan
	@echo "Scanner findings ingested. curl 'localhost:8000/findings?asset_id=scan-target-01'"

down: ## Stop the stack (keep data volumes)
	$(COMPOSE) down

clean: ## Stop the stack AND remove data volumes (destructive)
	$(COMPOSE) down -v

restart: ## Restart the stack
	$(COMPOSE) restart

ps: ## Show running services
	$(COMPOSE) ps

logs: ## Tail logs for all services
	$(COMPOSE) logs -f --tail=100

health: ## Curl the API liveness + readiness endpoints
	@echo "--- /health ---"   && curl -fsS http://localhost:8000/health   && echo
	@echo "--- /version ---"  && curl -fsS http://localhost:8000/version  && echo
	@echo "--- /health/ready ---" && curl -fsS http://localhost:8000/health/ready && echo

clone-refs: ## Shallow-clone all reference repos into reference/ (study only)
	bash scripts/clone-references.sh

seed: ## (Phase 1+) Seed databases / feed mirror — placeholder
	@echo "seed: not implemented until Phase 1"

test: ## (Phase 1+) Run test suites — placeholder
	@echo "test: not implemented until Phase 1"
