LOG-DIR:= .logs
DATA-DIR:= data
.PHONY: init lint test coverage

init:
	git config core.hooksPath .hooks
	mkdir $(LOG-DIR)
	mkdir $(DATA-DIR)

lint:
	pipenv run black -l 120 pylinks
	git ls-files -- . ':!:*__init__.py' -z | while IFS= read -rd '' f; do tail -c1 < "$f" | read -r _ || echo >> "$f"; done
	pipenv run isort -rc .

test:
	pipenv run python -m pytest --cov=pylinks tests --cov-report xml

coverage:
	pipenv run python -m pytest --cov=pylinks tests --cov-report term-missing

run-dev:
	@pipenv run uvicorn pylinks.app:app --reload