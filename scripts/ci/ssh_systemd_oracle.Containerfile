FROM docker.io/library/debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 container=podman
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus openssh-server util-linux iproute2 && rm -rf /var/lib/apt/lists/*
RUN systemctl mask ssh.service ssh.socket dev-mqueue.mount run-lock.mount tmp.mount systemd-ask-password-console.path systemd-ask-password-wall.path
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
