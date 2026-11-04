FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

ENV HOME=/var/lib/spamd

RUN apt-get update \
    && apt-get install --no-install-recommends --yes spamd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 spamd \
    && useradd --system --uid 10001 --gid 10001 \
        --home-dir /var/lib/spamd --create-home \
        --shell /usr/sbin/nologin spamd \
    && mkdir -p /mymail-data \
    && chown -R 10001:10001 /var/lib/spamd /mymail-data

USER 0:0
WORKDIR /var/lib/spamd

EXPOSE 783

ENTRYPOINT ["/usr/sbin/spamd"]
CMD ["--listen=127.0.0.1", "--port=783", "--allowed-ips=127.0.0.1", "--username=spamd", "--max-children=5", "--nouser-config", "--virtual-config-dir=/mymail-data/users/%u/spamassassin", "--pidfile=/tmp/spamd.pid", "--syslog=stderr"]