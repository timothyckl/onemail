FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        file \
        fonts-dejavu-core \
        libharfbuzz-subset0 \
        libimage-exiftool-perl \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libreoffice-calc \
        libreoffice-impress \
        libreoffice-writer \
        p7zip-full \
        poppler-utils \
        python3 \
        python3-venv \
        tesseract-ocr \
        yara \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        oletools==0.60.2 \
        pefile==2024.8.26 \
        pydyf==0.10.0 \
        pypdf==6.1.1 \
        speakeasy-emulator==2.0.0b6 \
        weasyprint==62.3

RUN useradd --create-home --shell /usr/sbin/nologin analyst \
    && mkdir -p /opt/onemail/rules \
    && chown -R root:root /opt/onemail

COPY runner.py /opt/onemail/runner.py
COPY rules/ /opt/onemail/rules/

LABEL org.opencontainers.image.title="OneMail isolated investigation" \
      onemail.os="ubuntu-24.04" \
      onemail.analysis="static-render-emulate"

USER analyst
WORKDIR /work
