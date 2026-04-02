<p align="center">
  <img src="https://img.shields.io/badge/ScanFlaws-v5.0-brightgreen?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/AWS-IAM%2FS3%2FEC2%2FLambda-orange?style=for-the-badge&logo=amazon-aws" alt="AWS">
  <img src="https://img.shields.io/badge/Security-Hardened-brightgreen?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<h1 align="center">🛡️ ScanFlaws</h1>
<p align="center">
  <strong>Enterprise-Grade AWS Security Risk Analysis Engine</strong><br>
  <em>Transforma hallazgos estáticos en análisis de riesgo inteligente</em>
</p>

<p align="center">
  <a href="#-features">✨ Features</a> •
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-architecture">🏗️ Architecture</a> •
  <a href="#-results">📊 Results</a> •
  <a href="#-security">🔐 Security</a> •
  <a href="#-contributing">🤝 Contributing</a>
</p>

---

## 🎯 Overview

**ScanFlaws** es una herramienta modular de auditoría de seguridad para AWS con **36+ checks automatizados** y un **motor de análisis de riesgo inteligente** que:

| 🔍 Detecta | 🧠 Analiza | 📊 Prioriza |
|-----------|-----------|------------|
| Configuraciones inseguras en IAM, S3, EC2, Lambda, ECR | Correlaciona hallazgos para riesgos compuestos | Scores 0-100 con contexto real |
| Credenciales expuestas, buckets públicos, puertos abiertos | Enriquece con exposición, producción, datos sensibles | Top-N risks con recomendaciones accionables |
| Políticas excesivas, keys antiguas, falta de MFA | Calcula vectores de ataque potenciales | Reportes ejecutivos para stakeholders |

> 💡 **Diferencial v5.0:** No solo lista vulnerabilidades — **entiende el riesgo real** y te dice qué arreglar primero.

---

## ✨ Features

### 🔍 Detección Avanzada

✅ 36 Security Checks Automatizados
├── 🛡️ Phase 1: Identity (20 checks)
│ ├── MFA, Access Keys, Políticas IAM, Roles
│ ├── Access Analyzer multi-región
│ ├── Key Rotation detection
│ └── Policy Simulator para escalada de privilegios
│
├── 🗄️ Phase 2: Storage (6 checks)
│ ├── S3: buckets públicos, versioning, cifrado, Object Lock
│ └── EBS: volúmenes sin cifrado, snapshots públicos
│
└── 🖥️ Phase 3: Compute (10 checks)
├── EC2: Security Groups, SSM Agent, AMIs públicas
├── Lambda: roles excesivos, env vars sin cifrar, X-Ray
└── ECR: scanning, repositorios públicos, lifecycle


### 🧠 Risk Analysis Engine v5.0
```python
# Nuevo pipeline inteligente
Hallazgos → Contexto → Correlación → Scoring → Output

📊 Scoring 0-100 basado en:
• Severidad base (INFO:5 → CRITICAL:80)
• Contexto: exposición pública (+20), producción (+10), datos sensibles (+15)
• Correlaciones: hallazgos relacionados (+5 c/u, máx +20)

🔗 Correlation Engine detecta:
• Usuario sin MFA + Access Key activa = 🔴 Credential Exposure (95/100)
• SG abierto + EC2 pública = 🔴 Public Compute Attack Path (92/100)
• S3 público + datos sensibles = 🔴 Data Exfiltration Risk (90/100)

🔐 SSecurity Hardening Enterprise
Command Injection
subprocess.run(..., shell=False) + whitelist
✅ Path Traversal sanitize_path() + UUID filenames + base dir validation
✅ Input Manipulation Unicode bypass detection + URL-decoding recursivo
✅ Sensitive Data Leak Auto-redaction en logs para keys, passwords, tokens
✅ Resource Exhaustion Rate limiting + timeouts + circuit breaker pattern
✅ Privilege Escalation Docker non-root user + read-only FS + cap-drop
✅ Type Confusion Pydantic v2 validation + isinstance() checks

📦 Output Profesional
🔴 ESTADO: CRITICAL_RISK
💬 Se detectaron 3 riesgo(s) crítico(s) que requieren atención inmediata

📈 Distribución por nivel de riesgo:
  CRITICAL     3 ████████████████████
  HIGH         1 ██████████
  MEDIUM       2 ██████████████
  LOW          4 ████████████████████████

🎯 TOP Riesgos Prioritarios:
  1. 🔴 Score: 100 | SG Puerto sensible abierto
     └─ Entidad: launch-wizard-1 (sg-xxx)
  2. 🔴 Score: 100 | SG Puerto sensible abierto
     └─ Entidad: launch-wizard-3 (sg-xxx)
  3. 🟠 Score:  70 | Usuarios sin MFA 🔗 Correlacionado
     └─ Entidad: haljr11
     └─ 🔗 Correlación: Access Keys activas en mismo usuario

💡 RECOMENDACIÓN: 🔴 ACCIÓN INMEDIATA: Remediar riesgos críticos

🚀 Quick Start
Prerrequisitos

# Python 3.12+
python --version

# AWS CLI configurado
aws configure list

# (Opcional) Docker para ejecución aislada
docker --version

Instalación:

# 1. Clonar repositorio
git clone https://github.com/DarkHama11/ScanFlaws.git
cd ScanFlaws

# 2. Crear entorno virtual (recomendado)
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# o
.venv\Scripts\activate     # Windows

# 3. Instalar dependencias
pip install -r requirements.txt

Configuración AWS:

# Opción A: AWS CLI (recomendado)
aws configure
# Ingresa: Access Key, Secret Key, región, formato output

# Opción B: Variables de entorno
export AWS_ACCESS_KEY_ID="tu_access_key"
export AWS_SECRET_ACCESS_KEY="tu_secret_key"
export AWS_DEFAULT_REGION="us-east-1"

# Opción C: Perfil específico
export AWS_PROFILE="mi-perfil-seguro"

Ejecución:
# 🔍 Auditoría completa (todas las fases)
python main.py

# 🎯 Ejecutar fases específicas
python -c "from main import run_all_phases; run_all_phases(['phase1', 'phase2'])"

# 🐳 Ejecutar en Docker (aislado y seguro)
docker build -t scanflaws:v5 .
docker run --rm \
  --memory=512m \
  --cpus=1 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  -v ~/.aws:/home/appuser/.aws:ro \
  scanflaws:v5

# 🧪 Ejecutar tests de seguridad
pytest tests/ -v --cov=core

# 🔎 Auditoría de dependencias
pip-audit

Output Files:

📁 Se generarán automáticamente:
├── scanflaws_risk_YYYYMMDD_HHMMSS.json  # Reporte completo con scoring
├── scanflaws_risk_YYYYMMDD_HHMMSS.csv   # Reporte tabular para Excel
└── (console)                            # Tabla legible + resumen ejecutivo

🏗️ Architecture:

graph TD
    A[main.py] --> B[Run Phases 1-3]
    B --> C[36 Security Checks]
    C --> D[Raw Findings List]
    
    D --> E[Risk Analysis Pipeline v5.0]
    
    subgraph RiskEngine["🧠 Risk Analysis Engine"]
        E --> F[Normalize → Finding Objects]
        F --> G[Context Enrichment]
        G --> H[Correlation Engine]
        H --> I[Risk Scoring 0-100]
        I --> J[Prioritization + Top-N]
    end
    
    J --> K[Enriched Output]
    K --> L[Console Table + Summary]
    K --> M[JSON Export]
    K --> N[CSV Export]
    
    style RiskEngine fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    style C fill:#fff3e0,stroke:#ef6c00
    style I fill:#e8f5e9,stroke:#2e7d32

Estructura del Proyecto:

ScanFlaws/
├── 📄 main.py                    # Orquestador principal v5.0
│
├── 📁 models/                    # Modelos de datos unificados
│   ├── __init__.py
│   └── finding.py               # Clase Finding + normalización
│
├── 📁 core/                      # Motor de análisis de riesgo
│   ├── risk_pipeline.py         # Pipeline: Hallazgos → Risk Output
│   ├── risk_engine/
│   │   ├── __init__.py
│   │   └── risk_calculator.py   # Scoring 0-100 + factores
│   ├── context_engine/
│   │   ├── __init__.py
│   │   └── context_builder.py   # Enriquecimiento de contexto
│   ├── correlation_engine/
│   │   ├── __init__.py
│   │   └── correlator.py        # Detección de riesgos compuestos
│   ├── reporter.py              # Exportación JSON/CSV + tablas
│   ├── aws_session.py           # Gestión de sesión AWS
│   └── security.py              # Validación de inputs + sanitización
│
├── 📁 phases/                    # Checks de seguridad por dominio
│   ├── phase1_identity/         # 20 checks IAM + avanzados
│   ├── phase2_storage/          # 6 checks S3 + EBS
│   └── phase3_compute/          # 10 checks EC2 + Lambda + ECR
│
├── 📁 tests/                     # Tests automatizados
│   ├── test_security.py         # 9 tests de hardening
│   └── test_advanced_security.py # 4 tests de validación avanzada
│
├── 📁 utils/                     # Utilidades helpers
│   ├── __init__.py
│   └── helpers.py
│
├── 📄 requirements.txt          # Dependencias Python
├── 📄 Dockerfile                # Container hardened
├── 📄 .dockerignore             # Exclusiones para Docker
├── 📄 .gitignore                # Exclusiones para Git
└── 📄 LICENSE                   # Licencia MIT

📊 Example Results
🔴 Critical Risk Scenario:

$ python main.py

🔴 ESTADO: CRITICAL_RISK
💬 Se detectaron 3 riesgo(s) crítico(s) que requieren atención inmediata

🎯 TOP Riesgos Prioritarios:
  1. 🔴 Score: 100 | SG Puerto sensible abierto
     └─ Entidad: launch-wizard-1 (sg-03a2989d564da96ef)
     └─ Issue: Puerto 22 (SSH) abierto a 0.0.0.0/0
     └─ Vector: Atacante puede escanear y brute-force SSH directamente

  2. 🔴 Score: 100 | SG Puerto sensible abierto  
     └─ Entidad: launch-wizard-3 (sg-08964d829d74b18f6)
     └─ Issue: Puerto 22 (SSH) abierto a 0.0.0.0/0

  3. 🟠 Score:  70 | Usuarios sin MFA 🔗 Correlacionado
     └─ Entidad: haljr11
     └─ Issue: Usuario IAM sin autenticación de dos factores
     └─ 🔗 Correlación: Access Keys activas en mismo usuario
     └─ Vector: Atacante puede usar access key para acceder sin MFA

💡 RECOMENDACIÓN: 🔴 ACCIÓN INMEDIATA: Remediar riesgos críticos antes de continuar operaciones

📈 Risk Distribution Chart (Console):
📈 Distribución por nivel de riesgo:
  CRITICAL     3 ████████████████████  ← Remediar YA
  HIGH         1 ██████████            ← Esta semana
  MEDIUM       2 ██████████████        ← Próximo sprint
  LOW          4 ████████████████████████  ← Monitoreo continuo

📄 JSON Export Snippet:

{
  "check": "Usuarios sin MFA",
  "entity": "haljr11",
  "severity": "HIGH",
  "score": 70,
  "risk_level": "HIGH",
  "context": {
    "is_public": false,
    "has_internet_exposure": false,
    "is_production": true,
    "has_sensitive_data": true
  },
  "correlated_findings": [
    {"check": "Access Key antigua", "entity": "haljr11"},
    {"check": "Access Key antigua", "entity": "haljr11"}
  ],
  "recommendation": "Habilitar MFA desde consola de AWS IAM"
}

🔐 Security Deep Dive
Input Validation Pipeline:

# 1. Normalización
normalize_input() → Decodifica bytes, remueve BOM, lowercase

# 2. URL-Decoding recursivo (previene bypass)
decode_url_encoded("example.com%253Bmalicious", max_depth=3)
# → "example.com;malicious" → DETECTADO ❌

# 3. Unicode Bypass Detection
UNICODE_BYPASS_PATTERNS = [
    r'[\u200B-\u200F]',  # Zero-width chars
    r'[\u202A-\u202E]',  # Directional overrides
    r'[\uFEFF]',          # BOM
]

# 4. Dangerous Character Blocking
DANGEROUS_CHARS = [';', '&', '|', '`', '$', '(', ')', ...]

# 5. Type Validation antes de .get()
if isinstance(context, dict):
    context.get("is_public")  # ✅ Seguro

-Pydantic v2 Structural Validation:
from models.finding import Finding

# Crear hallazgo con validación automática
finding = Finding(
    check="MFA Check",
    entity="admin-user", 
    severity="HIGH",  # → Normalizado a mayúsculas
    issue="Usuario sin autenticación de dos factores habilitada"  # min_length=10 ✅
)

# Validaciones automáticas:
# • severity: Enum validado + normalizado
# • issue: min_length=10 caracteres
# • check: max_length=200 caracteres
# • score: 0-100 con clamp automático

-Docker Hardening Flags:
# Ejecutar con máxima seguridad:
docker run --rm \
  --memory=512m \                    # Límite de memoria
  --cpus=1 \                         # Límite de CPU
  --read-only \                      # Filesystem de solo lectura
  --cap-drop=ALL \                   # Sin capacidades Linux
  --security-opt no-new-privileges \ # Sin escalation de privilegios
  --user 1000:1000 \                 # Usuario no-root
  scanflaws:v5

🤝 Contributing:

¡Las contribuciones son bienvenidas! 🎉
Flujo de Contribución:

# 1. Fork el repositorio
# 2. Crea tu branch de feature
git checkout -b feature/AmazingSecurityCheck

# 3. Desarrolla y testea
pytest tests/ -v
python main.py  # Verifica que no rompa funcionalidad

# 4. Commit con mensaje convencional
git commit -m "feat: add new S3 encryption check"
# o
git commit -m "fix: handle None context in risk calculator"

# 5. Push y crea Pull Request
git push origin feature/AmazingSecurityCheck



## Convenciones de Commit

| Tipo      | Descripción         | Ejemplo                                 |
|-----------|----------------------|------------------------------------------|
| feat:     | Nueva funcionalidad  | feat: add Lambda X-Ray check             |
| fix:      | Corrección de bug    | fix: handle empty findings list          |
| docs:     | Documentación        | docs: update README with v5.0 features   |
| test:     | Tests                | test: add validation for CVE format      |
| refactor: | Refactorización      | refactor: extract context builder module |
| security: | Hardening            | security: add Unicode bypass detection   |
-------------------------------------------------------------------------------
Checklist para PR:
Código sigue estilo PEP 8
Tests nuevos para funcionalidades nuevas
Todos los tests pasan (pytest tests/ -v)
Documentación actualizada si aplica
No hay secrets/credentials en el código
Cambios probados con cuenta AWS de testing

📄 License
Distribuido bajo la licencia MIT. Ver LICENSE para más información:

MIT License

Copyright (c) 2024 Harol (@DarkHama11)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

👤 Author
Harold

<p align="center">
<strong>🛡️ ScanFlaws: Security Intelligence for AWS</strong><br>
<em>De hallazgos a decisiones — con riesgo cuantificado.</em>
</p>

<p align="center">
<a href="https://github.com/DarkHama11/ScanFlaws/stargazers">
<img src="https://img.shields.io/github/stars/DarkHama11/ScanFlaws?style=social" alt="Stars">
</a>
<a href="https://github.com/DarkHama11/ScanFlaws/network/members">
<img src="https://img.shields.io/github/forks/DarkHama11/ScanFlaws?style=social" alt="Forks">
</a>
<a href="https://github.com/DarkHama11/ScanFlaws/issues">
<img src="https://img.shields.io/github/issues/DarkHama11/ScanFlaws" alt="Issues">
</a>
</p>

