# ScanFlaws — AWS IAM Security Scanner

Herramienta educativa en Python para auditar configuraciones inseguras en AWS IAM, inspirada en [flaws.cloud](https://flaws.cloud).

> ⚠️ **Uso ético**: Solo para auditorías en cuentas propias o con autorización explícita.

---

## 🔍 ¿Qué detecta?

✅ **Usuarios sin MFA** (autenticación multifactor)  
✅ **Access keys antiguas (>90 días)** o inactivas  
✅ **Políticas con privilegios excesivos** (`Resource: "*"` + acciones sensibles)  
✅ **Posibilidad de escalada de privilegios** (ej: `iam:PutUserPolicy`)  
✅ **Roles asumibles desde Internet** (`Principal: "*"` o cuentas externas)  
✅ **Hallazgos de IAM Access Analyzer** (si está habilitado)  
✅ **Usuarios inactivos (>90 días)**  
✅ **Permisos `iam:PassRole` sin restricciones**  
✅ **Permisos `sts:AssumeRole` sin restricciones**  
✅ **Políticas en línea (inline policies)** en usuarios o roles  
✅ **Permisos que permiten deshabilitar CloudTrail**

---

## 📦 Requisitos

- Python 3.8+  
- Credenciales AWS configuradas (`aws configure`)  
- Permisos de lectura en IAM y Access Analyzer (opcional)

---

## 🚀 Cómo usarlo

1. Clona el repositorio:
   ```bash
   git clone https://github.com/DarkHama11/ScanFlaws.git
   cd ScanFlaws
