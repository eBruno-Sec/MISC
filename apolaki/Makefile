# Apolaki — one-command environment control.
#
#   make up          core: agent + Juice Shop + intel-feeds  (UI at http://localhost:8000)
#   make full-lab    everything: core + labs + browser + proxy + dast, with lab DBs initialized
#   make init-labs   one-time DB/setup for DVWA / bWAPP / Mutillidae (idempotent)
#   make reset-labs  recreate the lab containers with fresh DBs, then re-init
#   make health      verify every running service is actually READY (not just "up")
#   make versions    tool + image version manifest (reproducibility)
#   make test        run the agent test suite in the built image
#   make ship-gate   bake-drift + suite + mutation gate (the checks that catch a green-but-wrong build)
#   make down        stop everything
#   make logs        tail the agent logs
#
# Requires Docker + docker compose. Scripts are POSIX sh (run under Git Bash on Windows).
COMPOSE ?= docker compose
FULL    := --profile labs --profile browser --profile proxy --profile dast

.PHONY: up full-lab init-labs reset-labs health versions test benchmark bake-check mutation-gate ship-gate down logs ps help

help:
	@echo "targets: up full-lab init-labs reset-labs health versions test ship-gate bake-check mutation-gate down logs ps"

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

bake-check:           ## FAIL if the running container has code that was never baked into the image
	@sh scripts/bake_drift_check.sh

mutation-gate:        ## FAIL if any mutant weakening a false-positive guard survives the test suite
	docker exec apolaki-agent-1 python /app/mutation_gate.py

ship-gate: bake-check ## the checks that catch a green-but-wrong build
	docker exec apolaki-agent-1 sh -c "cd /app && python -m pytest tests/ -q"
	docker exec apolaki-agent-1 python /app/mutation_gate.py
	@echo "ship-gate OK: image matches container, suite green, no surviving mutants"

benchmark:            ## artery-mechanism NO-MOCKS proof: register -> IDOR signal -> restart survives
	@sh scripts/benchmark.sh

benchmark-full:       ## FULL-MISSION NO-MOCKS proof: /engage -> /run -> deep correctness asserter
	@sh scripts/benchmark_full.sh

benchmark-fresh:      ## FULL-MISSION on a GENUINELY isolated fresh juice-shop-bench (never the user's lab)
	@sh scripts/benchmark_full.sh --fresh-lab --baseline

benchmark-repeat:     ## DETERMINISM: two independent fresh missions, deep-assert both, fail on drift
	@sh scripts/benchmark_repeat.sh

down:
	$(COMPOSE) $(FULL) down

logs:
	$(COMPOSE) logs --tail=120 -f agent

ps:
	$(COMPOSE) $(FULL) ps
