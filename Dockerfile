FROM docker.io/library/python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.22@sha256:f513a91fc62fe7c17567eee97230dd198e43edb8a9fbecca843714a4358fe1bc /uv /uvx /bin/

# ca-certificates for outbound https; nothing else is needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN UV_PROJECT_ENVIRONMENT=/app/.venv uv sync --frozen --no-install-project

COPY server.py outline.py config.py net.py fs_ops.py content.py ./

# Run as a non-root user: the filesystem scope is enforced in the server, and
# the container's own permissions are the backstop.
#
# The uid is a build arg because rootless runtimes do not remap a bind mount's
# ownership. Build with the host uid to bind-mount, or use a named volume,
# which the runtime chowns to this user on first use.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --gid "${APP_GID}" app \
    && useradd --create-home --uid "${APP_UID}" --gid "${APP_GID}" app
USER app

ENV PYTHONUNBUFFERED=1
CMD ["/app/.venv/bin/python", "server.py"]
