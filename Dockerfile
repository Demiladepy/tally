# One-command run of the bulletin + web app (offerings, order ticket, orders,
# clearing reports):
#   docker build -t tally .
#   docker run --rm -p 8787:8787 -v tally-data:/data tally
# then open http://127.0.0.1:8787
#
# The WebAssembly the browser runs is rebuilt here from source, the same way
# the Pages workflow builds it, and its sha256 is served next to it.
#
# The bulletin keeps no request logs. Its receipt key and auction logs live
# in the /data volume.
FROM rust:1.95-slim AS build
WORKDIR /src
RUN rustup target add wasm32-unknown-unknown
COPY . .
RUN cargo build --release --locked -p tally-bulletin \
 && cargo build --release --locked --target wasm32-unknown-unknown -p tally-wasm \
 && cp target/wasm32-unknown-unknown/release/tally_wasm.wasm web/tally_wasm.wasm \
 && (cd web && sha256sum tally_wasm.wasm > tally_wasm.wasm.sha256)

FROM debian:trixie-slim
RUN useradd --system --home /data tally && mkdir -p /data && chown tally /data
COPY --from=build /src/target/release/tally-bulletin /usr/local/bin/tally-bulletin
COPY --from=build /src/web /app/web
EXPOSE 8787
VOLUME /data
# A mounted volume (Docker or Fly) arrives owned by root. Hand it to the
# unprivileged user, then drop root before the bulletin starts.
CMD ["sh", "-c", "chown tally /data && exec setpriv --reuid=tally --regid=tally --init-groups tally-bulletin --listen 0.0.0.0:8787 --data /data --key /data/bulletin.key --web /app/web"]
