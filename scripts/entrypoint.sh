#!/bin/sh

chown -R vicarian:vicarian /var/lib/vicarian

exec su-exec vicarian /usr/bin/vicarian "$@"
