FROM python:3.12-slim-bookworm

COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY /entrypoint.sh /

COPY uv.lock pyproject.toml .

RUN uv sync --frozen --exact

COPY src src

CMD ["/entrypoint.sh"]
