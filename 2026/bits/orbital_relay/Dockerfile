FROM ubuntu:24.04 AS libs

FROM pwn.red/jail:0.3.0
ENV JAIL_PORT=1337
ENV JAIL_TIME=600
ENV JAIL_MEM=256M

COPY orbital_relay /srv/app/run
COPY flag.txt /srv/app/flag.txt

COPY --from=libs /lib/x86_64-linux-gnu/ /srv/lib/x86_64-linux-gnu/
COPY --from=libs /lib64/ld-linux-x86-64.so.2 /srv/lib64/ld-linux-x86-64.so.2

RUN chmod 755 /srv/app/run && chmod 644 /srv/app/flag.txt
