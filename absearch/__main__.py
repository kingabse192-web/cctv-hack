"""Allow ``python -m absearch`` as an alternative to the console script."""

from .cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
