# One-command run of the bulletin + web app (cases, verify, bid):
#   docker build -t tally .
#   docker run --rm -p 8787:8787 -v tally-data:/data tally
# then open http://127.0.0.1:8787
#
# The bulletin keeps no request logs. Its receipt key and auction logs live
# in the /data volume.
FROM rust:1.95-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p tally-bulletin

FROM debian:trixie-slim
RUN useradd --system --home /data tally && mkdir -p /data && chown tally /data
COPY --from=build /src/target/release/tally-bulletin /usr/local/bin/tally-bulletin
COPY web /app/web
USER tally
EXPOSE 8787
VOLUME /data
CMD ["tally-bulletin", "--listen", "0.0.0.0:8787", "--data", "/data", "--key", "/data/bulletin.key", "--web", "/app/web"]
