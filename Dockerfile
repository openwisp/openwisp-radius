# NOTE: This Docker image is for development purposes only.

FROM python:3.12-slim-bookworm

# System dependencies from the developer installation guide
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  xmlsec1 \
  gettext \
  fping \
  gdal-bin \
  libproj-dev \
  libgeos-dev \
  libspatialite-dev \
  spatialite-bin \
  libsqlite3-mod-spatialite \
  sqlite3 \
  libsqlite3-dev \
  zlib1g-dev \
  libjpeg-dev \
  openssl \
  libssl-dev \
  libglib2.0-0 \
  libcairo2 \
  libpango-1.0-0 \
  libpangocairo-1.0-0 \
  libgdk-pixbuf-2.0-0 \
  shared-mime-info \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openwisp/tests

# Install test requirements first so this layer is cached separately
# from the source code copy below.
COPY requirements-test.txt .
RUN pip install --no-cache-dir -r requirements-test.txt

# Copy source and install the package with all optional extras
COPY . .
RUN pip install --no-cache-dir -e ".[saml,openvpn_status]"

ENV PYTHONUNBUFFERED=1 \
  REDIS_HOST=redis \
  INFLUXDB_HOST=influxdb

EXPOSE 8000
CMD ["bash", "docker-entrypoint.sh"]
