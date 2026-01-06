# 🔍 ScanFlaws — AWS IAM Security Scanner

Herramienta educativa en Python para auditar configuraciones inseguras en **AWS IAM**, inspirada en [flaws.cloud](https://flaws.cloud).

> ⚠️ **Uso ético**: Solo para auditorías en cuentas propias o con autorización explícita.

---

## 🛡️ ¿Qué detecta?

- [x] Usuarios sin MFA (autenticación multifactor)
- [x] Access keys antiguas (>90 días) o inactivas
- [x] Políticas con privilegios excesivos (`Resource: "*"` + acciones sensibles)
- [x] Posibilidad de **escalada de privilegios** (ej: `iam:PutUserPolicy`)
- [x] Roles asumibles desde Internet (`Principal: "*"` o cuentas externas)
- [x] Hallazgos de **IAM Access Analyzer** (si está habilitado)

---

## 📦 Requisitos

- Python 3.8+
- Credenciales AWS configuradas (`aws configure`)
- Permisos de lectura en IAM y Access Analyzer (opcional)

---

## 🚀 Instalación y uso

```bash
# Clonar el repositorio
git clone https://github.com/DarkHama11/ScanFlaws.git
cd ScanFlaws

# Instalar dependencias
pip install boto3

# Configurar credenciales AWS (si no lo has hecho)
aws configure

# Ejecutar el escáner
python main.py
