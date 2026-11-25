S ?= s01
MODE ?= vulnerable
LLM ?= scripted
N ?= 1
export LAB_UID := $(shell id -u)
export LAB_GID := $(shell id -g)

COMPOSE := docker compose -f docker-compose.yml
ifneq ($(LLM),scripted)
COMPOSE += -f docker-compose.llm.yml
endif
IN_ATTACKER := $(COMPOSE) exec -T attacker python -m

.PHONY: ready up down reset attack attack-all detect test lint matrix demo

up:
	@mkdir -p runs
	$(COMPOSE) up -d --build --wait
	@$(IN_ATTACKER) scenarios.reset

down:
	docker compose -f docker-compose.yml -f docker-compose.llm.yml down

reset:
	@$(IN_ATTACKER) scenarios.reset

ready:
	@mkdir -p runs
	@$(COMPOSE) up -d --wait >/dev/null 2>&1 || (echo "lab did not start, run 'make up'"; exit 1)

attack: ready
	@$(IN_ATTACKER) scenarios.harness $(S) --mode $(MODE) --llm $(LLM) --repeat $(N) --target compose

attack-all: ready
	@$(IN_ATTACKER) scenarios.harness all --mode $(MODE) --llm $(LLM) --repeat $(N) --target compose

detect:
	@$(IN_ATTACKER) detections.evaluate

test:
	uv run --all-extras pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

matrix:
	uv run --all-extras python -m scenarios.matrix

demo: ready
	@echo "### 1. Vulnerable: app-only permissions, no checks"
	@$(IN_ATTACKER) scenarios.harness s01 --mode vulnerable --target compose
	@echo; echo "### Detections on the directory audit log"
	@$(IN_ATTACKER) detections.evaluate
	@echo; echo "### 2. Hardened: same ticket, same hijacked model"
	@$(IN_ATTACKER) scenarios.harness s01 --mode hardened --target compose
	@echo; echo "### Detections"
	@$(IN_ATTACKER) detections.evaluate
