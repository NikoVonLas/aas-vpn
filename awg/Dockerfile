FROM ghcr.io/wg-easy/wg-easy:15.4.0
RUN apk add --no-cache libcap
COPY prepare.mjs /tmp/aas-prepare.mjs
RUN node /tmp/aas-prepare.mjs && rm /tmp/aas-prepare.mjs && setcap cap_net_admin,cap_net_raw=ep /usr/sbin/capsh
COPY start.sh /usr/local/bin/aas-start
RUN chmod 0755 /usr/local/bin/aas-start && \
    touch /run/xtables.lock && chown 1000:65532 /run/xtables.lock && chmod 0600 /run/xtables.lock
USER 1000:65532
CMD ["/usr/sbin/capsh", "--inh=cap_net_admin,cap_net_raw", "--addamb=cap_net_admin,cap_net_raw", "--shell=/bin/sh", "--", "-c", "exec /usr/local/bin/aas-start"]
