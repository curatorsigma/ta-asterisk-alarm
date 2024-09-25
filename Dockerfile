FROM rust:1.80-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /usr/src/ta-asterisk-alarm
COPY . .
RUN cargo build --release
CMD ["ta-asterisk-alarm"]

FROM alpine:latest
WORKDIR /ta-asterisk-alarm
COPY --from=builder /usr/src/ta-asterisk-alarm/target/release/ta-asterisk-alarm ./
CMD ["./ta-asterisk-alarm"]

