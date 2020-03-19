.PHONY: hooks lint test coverage

hooks:
	git config core.hooksPath .hooks

lint:
	pipenv run black -l 120 pylinks
	git ls-files -- . ':!:*__init__.py' -z | while IFS= read -rd '' f; do tail -c1 < "$f" | read -r _ || echo >> "$f"; done
	pipenv run isort -rc .

test:
	pipenv run python -m pytest --cov=pylinks tests --cov-report xml

coverage:
	pipenv run python -m pytest --cov=pylinks tests --cov-report term-missing