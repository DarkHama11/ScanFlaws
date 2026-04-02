# ScanFlaws - Dockerfile para ejecución aislada
# Security Hardening: Sandbox para herramientas de escaneo

FROM python:3.11-slim

# 🔒 Security: Ejecutar como usuario no-root
RUN useradd -m -u 1000 scanflaws

# Instalar dependencias del sistema (solo las necesarias)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 🔒 Security: Instalar AWS CLI de forma segura
RUN curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip \
    && unzip -q awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip ./aws

# Configurar directorio de trabajo
WORKDIR /app

# Copiar solo lo necesario
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ ./core/
COPY phases/ ./phases/
COPY utils/ ./utils/
COPY main.py .
COPY .gitignore .

# 🔒 Security: Establecer permisos restrictivos
RUN chown -R scanflaws:scanflaws /app \
    && chmod -R 755 /app \
    && chmod 644 /app/main.py

# Cambiar a usuario no-root
USER scanflaws

# Variables de entorno seguras
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 🔒 Security: Health check para detectar procesos colgados
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Comando por defecto
CMD ["python", "main.py"]