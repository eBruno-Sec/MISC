# Apolaki — one-command environment control.
#
#   make up          core: agent + Juice Shop + intel-feeds  (UI at http://localhost:8000)
#   make full-lab    everything: core + labs + browser + proxy + dast, with lab DBs initialized
#   make init-labs   one-time DB/setup for DVWA / bWAPP / Mutillidae (idempotent)
#   make reset-labs  recreate the lab containers with fresh DBs, then re-init
#   make health      verify every running service is actually READY (not just "up")
#   make versions    tool + image version manifest (reproducibility)
#   make test        run the agent test suite in the built image
#   make down        stop everything
#   make logs        tail the agent logs
#
# Requires Docker + docker compose. Scripts are POSIX sh (run under Git Bash on Windows).
COMPOSE ?= docker compose
FULL    := --profile labs --profile browser --profile proxy --profile dast

.PHONY: up full-lab init-labs reset-labs health versions test down logs ps help

help:
	@echo "targets: up full-lab init-labs reset-labs health versions test down logs ps"

up:
	$(COMPOSE) up -d --build
	@echo "Apolaki UI -> http://localhost:8000"

full-lab:
	$(COMPOSE) $(FULL) up -d --build
	@sh scripts/init-labs.sh
	@echo "Apolaki UI -> http://localhost:8000  |  labs: DVWA :42080  bWAPP :42088  Mutillidae :42089  Juice Shop :42000"

init-labs:
	@sh scripts/init-labs.sh

reset-labs:
	-$(COMPOSE) $(FULL) rm -sfv dvwa bwapp mutillidae juice-shop
	$(COMPOSE) $(FULL) up -d dvwa bwapp mutillidae juice-shop
	@sh scripts/init-labs.sh

health:
	@sh scripts/health.sh

versions:
	@sh scripts/versions.sh

test:
	$(COMPOSE) build agent
	docker run --rm -v "$(CURDIR)/agent:/app" -w /app apolaki-agent:latest python -m pytest tests/ -q

down:
	$(COMPOSE) $(FULL) down

logs:
	$(COMPOSE) logs --tail=120 -f agent

ps:
	$(COMPOSE) $(FULL) ps
