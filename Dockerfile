# syntax=docker/dockerfile:1

###############################################################################
# Build stage
###############################################################################
FROM rust:alpine AS build

RUN apk add --no-cache build-base cmake perl

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY scripts/entrypoint.sh ./
RUN cargo build --release

###############################################################################
# Runtime stage
###############################################################################
FROM alpine:3.23

RUN apk add --no-cache libcap \
    && addgroup -S -g 65532 vicarian \
    && adduser -S -D -H -u 65532 -G vicarian vicarian \
    && mkdir -p /etc/vicarian /var/lib/vicarian/acme \
    && chown vicarian:vicarian /etc/vicarian /var/lib/vicarian

COPY --from=build /app/target/release/vicarian /usr/bin/vicarian
COPY --from=build /app/entrypoint.sh /usr/bin/entrypoint.sh

RUN setcap cap_net_bind_service+ep /usr/bin/vicarian

USER vicarian

EXPOSE 80 443

# ACME state (certificates, keys and account info); mount a named volume to persist it.
VOLUME ["/var/lib/vicarian"]

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
CMD ["-v"]

# Usage:
#
#     docker build -t vicarian .
#
#     docker run -d --name vicarian \
#       -p 80:80 -p 443:443 \
#       -v /path/to/etc/vicarian:/etc/vicarian/:ro \
#       -v vicarian-state:/var/lib/vicarian \
#       vicarian
#
# DNS-01 provider credentials can be passed as environment variables, e.g.:
#
#   docker run -e REG_CLOUDFLARE_API_TOKEN=... ...
#
# Alternatively the file /path/to/etc/vicarian/secrets can be created with the format:
#
#     MY_SECRET_NAME = MY_SECRET_VALUE
#
