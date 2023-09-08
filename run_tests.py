#!/usr/bin/env python
import subprocess
import sys


def main():
    environment_name = sys.argv[1]

    if "drf" in environment_name:
        subprocess.run(["python", "-m", "pytest", "tests/test_rest_framework/"])
    elif "fastapi" in environment_name:
        subprocess.run(["python", "-m", "pytest", "tests/test_fastapi/"])
    else:
        print(f"Unknown environment: {environment_name}")  # noqa T201
        sys.exit(1)


if __name__ == "__main__":
    main()
