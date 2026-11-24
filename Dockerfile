FROM ubuntu:26.04

ARG TARGETARCH

# Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash ttyd

# Application
COPY ./dist/${TARGETARCH}/ttyd /usr/bin/ttyd

EXPOSE 7681
WORKDIR /home/ttyd
# Do not hand out a root shell by default; use `--user root` if you really
# want the old behaviour.
USER ttyd

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["ttyd", "-W", "bash"]
