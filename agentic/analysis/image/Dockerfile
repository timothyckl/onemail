FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        clamav \
        file \
        libimage-exiftool-perl \
        p7zip-full \
        python3 \
        python3-venv \
        yara \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        oletools==0.60.2 \
        pefile==2024.8.26 \
        pypdf==6.1.1

RUN useradd --create-home --shell /usr/sbin/nologin analyst \
    && mkdir -p /opt/onemail/rules /opt/onemail/signatures/clamav \
    && chown -R root:root /opt/onemail

COPY runner.py /opt/onemail/runner.py
COPY rules/ /opt/onemail/rules/
COPY signatures/clamav/ /opt/onemail/signatures/clamav/

LABEL org.opencontainers.image.title="OneMail static analysis" \
      onemail.os="ubuntu-24.04" \
      onemail.analysis="static"

USER analyst
WORKDIR /work
