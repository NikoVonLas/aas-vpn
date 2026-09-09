FROM alpine:3.24 AS tools-build
RUN apk add --no-cache build-base git linux-headers
RUN git clone --depth 1 --branch v3.0.20260805 https://github.com/amnezia-vpn/amneziawg-tools.git /src
RUN make -C /src/src -j2 WIREGUARD_TOOLS_VERSION=3.0.20260805

FROM python:3.13-alpine
RUN apk add --no-cache iproute2 iptables libcap && \
    setcap cap_net_admin,cap_net_raw=ep /usr/sbin/capsh && \
    touch /run/xtables.lock && chown 1000:65532 /run/xtables.lock && chmod 0600 /run/xtables.lock
COPY --from=tools-build /src/src/wg /usr/bin/awg
COPY --from=tools-build /src/COPYING /usr/share/licenses/amneziawg-tools/COPYING
WORKDIR /app
COPY awg/*.py ./
USER 1000:65532
ENTRYPOINT ["/usr/sbin/capsh", "--inh=cap_net_admin,cap_net_raw", "--addamb=cap_net_admin,cap_net_raw", "--shell=/bin/sh", "--", "-c", "exec python controller.py"]
