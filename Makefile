  
format:
	isort .
	black .

lint:
	black --diff --check .
	isort -c --diff .
	flake8 .
#	mypy

.PHONY: format lint