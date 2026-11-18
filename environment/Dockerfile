# The image used for evaluation is additionally identified by its content ID.
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
ARG DEBIAN_SNAPSHOT=20261110T000000Z
RUN printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends gcc g++ binutils git make libc6-dev zlib1g-dev \
    && dpkg-query -W > /opt/patchcheck-packages.lock \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=C LC_ALL=C TZ=UTC
LABEL org.patchcheck.environment="1.0" org.patchcheck.snapshot="20261110T000000Z"
