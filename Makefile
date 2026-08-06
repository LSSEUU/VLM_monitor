.PHONY: install format format-check lint typecheck test e2e schemas schemas-check m4-coverage m5-coverage demo quality

install:
	uv sync --all-groups --locked

format:
	uv run --locked ruff format src tests scripts
	uv run --locked ruff check --fix src tests scripts

format-check:
	uv run --locked ruff format --check src tests scripts

lint:
	uv run --locked ruff check src tests scripts

typecheck:
	uv run --locked mypy

test:
	uv run --locked pytest

e2e:
	uv run --locked pytest tests/e2e

schemas:
	uv run --locked python scripts/export_schemas.py

schemas-check:
	uv run --locked python scripts/export_schemas.py --check

m4-coverage:
	uv run --locked pytest \
		tests/unit/test_m4_hearing_domain.py \
		tests/unit/test_m4_hearing_budget.py \
		tests/contract/test_m4_acquisition_matrix.py \
		tests/unit/test_m4_hearing_rework.py \
		--cov=labcourt.domain.hearing_fsm \
		--cov=labcourt.application.hearing_budget \
		--cov=labcourt.contracts.acquisition_matrix \
		--cov=labcourt.application.hearing_rework \
		--cov-branch \
		--cov-report=term-missing \
		--cov-fail-under=100

m5-coverage:
	uv run --locked pytest \
		tests/unit/test_m5_appeal_fsm.py \
		tests/unit/test_m5_alert_policy.py \
		tests/unit/test_m5_precedent_conflict_policy.py \
		tests/unit/test_m5_training_quality_gate.py \
		--cov=labcourt.domain.appeal_fsm \
		--cov=labcourt.domain.alert_policy \
		--cov=labcourt.domain.precedent_conflict_policy \
		--cov=labcourt.domain.training_quality_gate \
		--cov-branch \
		--cov-report=term-missing \
		--cov-fail-under=100

demo:
	uv run --locked python scripts/run_m6_demo.py

quality: format-check lint typecheck test schemas-check m4-coverage m5-coverage
