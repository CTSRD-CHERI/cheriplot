

test:
	python -m pytest tests/

test-prov:
	python -m pytest tests/provenance/

coverage:
	python -m pytest --cov=cheriplot --cov-report html:docs/coverage tests/
