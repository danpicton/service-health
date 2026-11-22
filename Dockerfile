# syntax=docker/dockerfile:1.7
# The platform and both upstream artifacts are fixed so a rebuild selects the same inputs.
FROM --platform=linux/amd64 python:3.14.10-slim-bookworm@sha256:5dca57ddc56794d9049dee9ee95a7f071b69d3b018368f2ddc61813649ca2fa0 AS trivy-bin
ADD --checksum=sha256:bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf \
    https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz /tmp/trivy.tar.gz
RUN tar -xzf /tmp/trivy.tar.gz -C /tmp trivy && /tmp/trivy --version

FROM --platform=linux/amd64 python:3.14.10-slim-bookworm@sha256:5dca57ddc56794d9049dee9ee95a7f071b69d3b018368f2ddc61813649ca2fa0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/service-health \
    XDG_CACHE_HOME=/var/cache/service-health
WORKDIR /opt/service-health
RUN install -d -o 65532 -g 65532 /var/lib/service-health /var/cache/service-health/trivy
COPY --from=trivy-bin /tmp/trivy /usr/local/bin/trivy
COPY src/service_health/*.py /opt/service-health/service_health/
USER 65532:65532
EXPOSE 8080
VOLUME ["/var/lib/service-health", "/var/cache/service-health"]
ENTRYPOINT ["python", "-m", "service_health"]
CMD ["--db", "/var/lib/service-health/state.db", "--host", "0.0.0.0", "--port", "8080"]
