# Build with --build-arg SWITCHLAB_IMAGE=<verified-current-image-reference>.
# Replaces CPython only; the application, site-packages, pip, and OS stay intact.
ARG SWITCHLAB_IMAGE
FROM python:3.13.18-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1 AS python-donor
RUN mkdir -p /python/usr/local/bin /python/usr/local/lib/pkgconfig /python/usr/local/include \
    && cp -a /usr/local/include/python3.13 /python/usr/local/include/ \
    && cp -a /usr/local/lib/libpython3* /python/usr/local/lib/ \
    && cp -a /usr/local/lib/python3.13 /python/usr/local/lib/ \
    && rm -rf /python/usr/local/lib/python3.13/site-packages \
    && cp -a /usr/local/lib/pkgconfig/python*.pc /python/usr/local/lib/pkgconfig/ \
    && cp -a /usr/local/bin/python* /usr/local/bin/pydoc* /usr/local/bin/idle* /python/usr/local/bin/

FROM ${SWITCHLAB_IMAGE}
USER 0:0
# Remove the old standard library before merging the donor. Keep every installed
# third-party package and entry point, including pip, byte-for-byte unchanged.
RUN find /usr/local/lib/python3.13 -mindepth 1 -maxdepth 1 ! -name site-packages -exec rm -rf -- {} + \
    && rm -rf /usr/local/include/python3.13 \
    && rm -f /usr/local/lib/libpython3* /usr/local/lib/pkgconfig/python*.pc \
        /usr/local/bin/python* /usr/local/bin/pydoc* /usr/local/bin/idle*
COPY --from=python-donor /python/usr/local/ /usr/local/
ENV PYTHON_VERSION=3.13.18 PYTHON_SHA256=abb0102e6d4ae027509bcb82327d9dd85515b44a3ba8ad538cfc5e9847029f68
RUN python -c "import ssl, sys, sysconfig; assert sys.version_info[:3] == (3, 13, 18); assert sysconfig.get_config_var('SOABI') == 'cpython-313-x86_64-linux-gnu'"
USER 10001:10001
