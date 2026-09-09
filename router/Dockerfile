FROM ghcr.io/sagernet/sing-box:v1.13.15 AS singbox
FROM python:3.13-alpine
RUN apk add --no-cache curl iproute2 libcap nftables
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
RUN setcap cap_net_admin,cap_net_raw=ep /usr/sbin/capsh
WORKDIR /app
COPY portal/routing.py router/controller.py ./
USER 65532:65532
ENTRYPOINT ["/usr/sbin/capsh", "--inh=cap_net_admin,cap_net_raw", "--addamb=cap_net_admin,cap_net_raw", "--shell=/bin/sh", "--", "-c", "exec python controller.py"]
