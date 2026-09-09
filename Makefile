# Project KESTREL — task runner. Targets are filled in phase by phase.
PY?=python
VENV=.venv
PIP=$(VENV)/Scripts/pip
PYV=$(VENV)/Scripts/python

.PHONY: help venv range-up range-down seed emulate detect report test clean
help:
	@echo "venv       - create local venv + install defensive tooling"
	@echo "range-up   - start the lightweight Kestrel Pay range (SQLite profile)"
	@echo "range-down - stop the range"
	@echo "seed       - build synthetic DB + emit benign baseline telemetry"
	@echo "emulate    - run a benign adversary scenario  (SCENARIO=scattered-sable)"
	@echo "detect     - compile+run Sigma detections over collected telemetry"
	@echo "report     - regenerate metrics + dashboards from evidence"
	@echo "test       - run detection unit tests"

venv:
	$(PY) -m venv $(VENV) && $(PIP) install -r requirements.txt

range-up:
	docker compose up -d kestrel-api nginx

range-down:
	docker compose down

run-app:      ## run the real vulnerable app locally (no Docker): http://127.0.0.1:8080
	cd range/kestrel-api && KESTREL_LOG_DIR=../data/logs $(PY) -m uvicorn app.main:app --host 127.0.0.1 --port 8080

live-attack:  ## drive the REAL running app over HTTP + record vulnerable responses
	$(PY) scripts/live_attack.py --base http://127.0.0.1:8080

scan:         ## run the security scanners locally (bandit/pip-audit/detect-secrets)
	$(PY) -m bandit -r range/kestrel-api/app -f txt || true
	$(PY) -m detect_secrets scan range/kestrel-api cloud-security docker-compose.yml
	$(PY) -m pip_audit -r range/kestrel-api/requirements.txt || true

seed:
	cd range/kestrel-api && $(PY) seed.py

emulate:
	$(PY) attack-scenarios/$(SCENARIO)/run.py

detect:
	$(PY) automation/detect/run_sigma.py

triage:
	$(PY) automation/soar/triage.py

report:
	$(PY) automation/report/build_report.py
	$(PY) automation/report/build_visuals.py
	$(PY) automation/report/build_social.py

test:
	$(PYV) -m pytest -q detections/tests
