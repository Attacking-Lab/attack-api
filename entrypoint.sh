#!/bin/sh

uv run --no-sync src/main.py # setup tables and sync

cd src
uv run --no-sync gunicorn -c gunicorn.conf.py main:app
