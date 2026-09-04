FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends janus nginx-light tini curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY config/ /etc/webrtc-demo/
COPY public/ /srv/webrtc-demo/
COPY entrypoint.sh /usr/local/bin/webrtc-demo
RUN chmod +x /usr/local/bin/webrtc-demo
EXPOSE 8080/tcp 20000-20100/udp
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:8080/janus/info || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/webrtc-demo"]
