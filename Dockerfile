# syntax=docker/dockerfile:1.7
#
# Baut NetPulse für amd64 (PC, Synology/QNAP mit Intel/AMD) und arm64 (Raspberry Pi 4/5, ARM-NAS).
# Kompiliert wird immer auf der Architektur des Build-Rechners (schnell), für die
# Zielarchitektur wird bei Bedarf ein Cross-Compiler verwendet.

# ---------- Build-Stage ----------
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG TARGETARCH
WORKDIR /src

RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu;  gcc=gcc-x86-64-linux-gnu;  libc=libc6-dev-amd64-cross ;; \
      arm64) target=aarch64-unknown-linux-gnu; gcc=gcc-aarch64-linux-gnu; libc=libc6-dev-arm64-cross ;; \
      *) echo "Nicht unterstützte Architektur: $TARGETARCH (bitte 64-Bit-Betriebssystem verwenden)"; exit 1 ;; \
    esac; \
    echo "$target" > /rust-target; \
    rustup target add "$target"; \
    if [ "$(dpkg --print-architecture)" != "$TARGETARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends "$gcc" "$libc" && rm -rf /var/lib/apt/lists/*; \
    fi

# Linker und C-Compiler je Zielarchitektur (ring – die Kryptobibliothek für TLS/SSH – enthält C-Code)
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar

COPY backend/ ./
# Cache-Mounts: Abhängigkeiten werden beim nächsten Build nicht neu kompiliert.
# sharing=locked: amd64- und arm64-Build laufen parallel und dürfen nicht gleichzeitig schreiben.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    target="$(cat /rust-target)"; \
    cargo build --release --target "$target"; \
    cp "target/$target/release/netpulse" /netpulse

# ---------- Laufzeit-Stage ----------
FROM debian:bookworm-slim

# setcap: erlaubt dem Programm ICMP-Ping ohne root-Rechte (nur Capability NET_RAW)
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libcap2-bin; \
    useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin netpulse; \
    mkdir -p /data && chown netpulse /data && chmod 700 /data; \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /netpulse /usr/local/bin/netpulse
COPY web/ /app/web/
COPY LICENSE TRADEMARK.md /app/

RUN setcap cap_net_raw+ep /usr/local/bin/netpulse \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y

ENV WEB_DIR=/app/web \
    DATA_DIR=/data
# Enthält den Tresor-Schlüssel für Zugangsdaten – als Volume einbinden und mitsichern!
VOLUME /data
WORKDIR /app
USER netpulse
ENTRYPOINT ["/usr/local/bin/netpulse"]
