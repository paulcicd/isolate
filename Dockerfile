FROM ubuntu:24.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y \
        vim \
        sudo \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        openssh-server \
        libpam-oath \
        liboath0 \
        liboath-dev \
        oathtool \
        caca-utils \
        qrencode \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/* \
    && mkdir /var/run/sshd \
    && useradd auth \
    && echo "%auth ALL=(auth) NOPASSWD: /opt/auth/wrappers/ssh.py" >> /etc/sudoers \
    && echo "[ -f /opt/auth/shared/bash.sh ] && source /opt/auth/shared/bash.sh" >> /etc/bash.bashrc

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --break-system-packages -r /tmp/requirements.txt

EXPOSE 22

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
