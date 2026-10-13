FROM python:3.12-slim

WORKDIR /app

# Install system dependencies including SoftHSM and build tools
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    default-libmysqlclient-dev \
    pkg-config \
    softhsm2 \
    libsofthsm2 \
    opensc \
    openssl \
    netcat-openbsd \
    gettext \
    librsync-dev \
    swig \
    libcairo2-dev \
    libgirepository1.0-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directories for SoftHSM BEFORE copying anything
RUN mkdir -p /var/lib/softhsm/tokens && \
    chmod 755 /var/lib/softhsm/tokens && \
    mkdir -p /etc/softhsm

# Create SoftHSM configuration in /etc (standard location)
RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf

# Set SoftHSM configuration environment variable
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# Copy requirements and install Python dependencies
COPY SecurityLogger/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY SecurityLogger/ .

EXPOSE 8000

CMD ["sh", "/app/entrypoint.sh"]