.PHONY: clean clean-test clean-pyc clean-build help setup lint test test-all test-cov coverage release dist install
.DEFAULT_GOAL := help

define BROWSER_PYSCRIPT
import os, webbrowser, sys
from urllib.request import pathname2url
webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys
for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	find . -name '*.egg-info' -exec rm -fr {} +

clean-pyc: ## remove Python bytecode artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

setup: ## install editable development, test, lint and release dependencies
	python -m pip install -e ".[test,lint,release]"

lint: ## run static checks
	pylint --rcfile .pylintrc -f parseable firepit
	bandit -ll -ii -r firepit

test: ## run tests with the default Python
	python -m pytest

test-all: ## run tests on every supported Python version with tox
	tox

test-cov: ## run tests with coverage assessment
	python -m pytest --cov=firepit --cov-report=xml

coverage: ## generate a local HTML coverage report
	coverage run --source firepit -m pytest
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

release: dist ## upload built packages
	python -m twine upload dist/*

dist: clean ## build source and wheel packages through PEP 517
	python -m build
	ls -l dist

install: clean ## install the package into the active Python environment
	python -m pip install .
