FROM ghcr.io/sagernet/sing-box:v1.13.15 AS singbox
FROM python:3.13-alpine
RUN apk add --no-cache iproute2 nftables curl
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
WORKDIR /app
COPY portal/routing.py router/controller.py ./
ENTRYPOINT ["python", "controller.py"]
