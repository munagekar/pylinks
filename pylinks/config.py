import environ  # type: ignore


@environ.config()
class Env:
    key = environ.var(name="SECRET_KEY", help="Secret key")


def read_from_env() -> Env:
    return environ.to_config(Env)
