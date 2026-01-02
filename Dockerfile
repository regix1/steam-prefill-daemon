FROM ubuntu:20.04
LABEL maintainers="tpilius@gmail.com;kirbo@kirbo-designs.com;regix1"

RUN \
        apt update \
        && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
                ca-certificates \
                libncursesw5 \
                locales \
                tzdata \
        && sed -i '/en_US.UTF-8/s/^# //' /etc/locale.gen \
        && dpkg-reconfigure --frontend=noninteractive locales \
        && update-locale LANG=en_US.UTF-8 \
        && rm -rf /var/cache/apt/archives /var/lib/apt/lists/*

ENV \
        LANG=en_US.UTF-8 \
        LANGUAGE=en_US:en \
        LC_ALL=en_US.UTF-8 \
        TERM=xterm-256color \
        HOME=/app

# Create app directory structure
WORKDIR /app

# Create directories for daemon mode and config persistence
RUN mkdir -p /commands /responses /app/Config /app/.cache

COPY /publish/SteamPrefill /app/SteamPrefill
RUN chmod +x /app/SteamPrefill

# Volumes for persistence and daemon communication
VOLUME ["/commands", "/responses", "/app/Config", "/app/.cache"]

ENTRYPOINT [ "/app/SteamPrefill" ]
