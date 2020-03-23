LOG_DIR:= .logs
DATA_DIR:= data
.PHONY: init lint test coverage openweb run-dev cleandb


init:
	git config core.hooksPath .hooks
	mkdir $(LOG_DIR)
	mkdir $(DATA_DIR)

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

openweb:
	open http:://localhost:8000

cleandb:
	rm data/test.db