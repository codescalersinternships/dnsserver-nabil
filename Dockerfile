# Stage 1: Build Stage
FROM rust:slim as builder

RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools

WORKDIR /src

COPY . /src

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/dnsserver-nabil /app/dnsserver-nabil

# Ensure the binary is executable
RUN chmod +x /app/dnsserver-nabil

EXPOSE 2053/udp

CMD ["./dnsserver-nabil"]
