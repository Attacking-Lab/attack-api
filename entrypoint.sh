#!/bin/sh

set -e

uv run --no-sync src/main.py -c /config.json

cd src
uv run --no-sync gunicorn -c gunicorn.conf.py main:app
