#!/bin/bash
# Make sure that the `pre-commit` and `flake8` packages are already
# installed in the running environment.

pre-commit run -a
flake8 .
