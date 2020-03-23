import uvicorn  # type: ignore

from pylinks.app import app


def run():
    uvicorn.run(app, host="0.0.0.0", interface="wsgi", port=80, log_level="info")


if __name__ == "__main__":
    run()
