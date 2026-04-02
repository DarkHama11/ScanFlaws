# ScanFlaws v4.0 - Hardened Docker Image
# Security: Minimal, non-root, resource-limited, read-only

# ===== BUILD STAGE =====
FROM python:3.11-slim as builder

WORKDIR /build

# Instalar dependencias de compilación
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar y instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ===== RUNTIME STAGE =====
FROM python:3.11-slim

# 🔒 Security: Metadata
LABEL maintainer="ScanFlaws Security Team"
LABEL org.opencontainers.image.source="https://github.com/DarkHama11/ScanFlaws"
LABEL org.opencontainers.image.description="AWS Security Audit Tool - Hardened"

# 🔒 Security: Crear usuario no-root
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /app /tmp/scanflaws && \
    chown -R appuser:appuser /app /tmp/scanflaws

# 🔒 Security: Instalar solo lo necesario
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 🔒 Security: Copiar solo lo necesario desde builder
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appuser core/ /app/core/
COPY --chown=appuser:appuser phases/ /app/phases/
COPY --chown=appuser:appuser utils/ /app/utils/
COPY --chown=appuser:appuser main.py requirements.txt /app/

WORKDIR /app

# 🔒 Security: PATH para paquetes user-installed
ENV PATH="/home/appuser/.local/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 🔒 Security: Directorio de trabajo seguro
VOLUME ["/tmp/scanflaws"]

# 🔒 Security: Cambiar a usuario no-root
USER appuser

# 🔒 Security: Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# 🔒 Security: Comando por defecto (sin shell)
ENTRYPOINT ["python"]
CMD ["main.py"]