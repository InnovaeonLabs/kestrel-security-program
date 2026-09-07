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

seed:
	cd range/kestrel-api && $(PY) seed.py

emulate:
	$(PY) attack-scenarios/$(SCENARIO)/run.py

detect:
	$(PY) automation/detect/run_sigma.py

report:
	$(PY) automation/report/build_report.py

test:
	$(PYV) -m pytest -q detections/tests
