#!/usr/bin/env python3
import sys

from paseto_forge.services.paseto_service import PasetoService


def main() -> None:
    keys = PasetoService.generate_keys()
    export_mode = "--env" in sys.argv

    for name, value in keys.items():
        if export_mode:
            print(f"export {name}={value}")
        else:
            print(f"{name}={value}")


if __name__ == "__main__":
    main()
