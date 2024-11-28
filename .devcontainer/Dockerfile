# Start with the Debian 12 (bookworm) image
FROM mcr.microsoft.com/devcontainers/base:bookworm

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
    libargon2-1 \
    libargon2-dev \
    postgresql-17 \
    postgresql-client-17 \
    postgresql-contrib-17 \
    libpq-dev=17.2-1.pgdg120+1 \
    gdb \
    && apt-get clean
