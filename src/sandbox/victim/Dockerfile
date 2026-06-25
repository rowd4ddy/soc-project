FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    rsyslog \
    openssh-server \
    iptables \
    net-tools \
    procps \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# SSH setup — weak auth intentionally so brute force generates real auth.log entries
RUN mkdir /var/run/sshd \
    && echo 'root:victim-demo-pw' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# rsyslog config — write auth/security events to auth.log, everything else to syslog
RUN echo 'auth,authpriv.*    /var/log/auth.log' >> /etc/rsyslog.conf \
    && echo '*.info;auth,authpriv.none    /var/log/syslog' >> /etc/rsyslog.conf

# nginx minimal page
RUN echo '<h1>Victim web service</h1>' > /var/www/html/index.html

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80

ENTRYPOINT ["/entrypoint.sh"]