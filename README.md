# 🛡️ ScanFlaws — Escáner de Seguridad para AWS IAM

**ScanFlaws** es una herramienta educativa en Python diseñada para identificar configuraciones inseguras en **AWS IAM (Identity and Access Management)**.  
Está inspirada en el famoso reto [flaws.cloud](https://flaws.cloud) y busca ayudarte a detectar malas prácticas antes de que un atacante las explote.

> ⚠️ **Importante**: Esta herramienta es **solo para uso ético**.  
> Úsala únicamente en cuentas AWS que te pertenezcan o en las que tengas **permiso explícito por escrito**.

---

## 🔍 ¿Qué hace ScanFlaws?

ScanFlaws analiza tu entorno AWS y reporta riesgos críticos en la configuración de IAM, como:

### 👤 Gestión de identidades
- Usuarios sin **MFA (autenticación multifactor)**
- Usuarios **inactivos más de 90 días**
- **Access keys antiguas** (>90 días) o nunca usadas

### 🔐 Políticas y permisos
- Políticas con `Resource: "*"` (permisos demasiado amplios)
- Asignación directa de políticas administrativas (`AdministratorAccess`)
- Permisos peligrosos:
  - `iam:PassRole` sin restricciones
  - `sts:AssumeRole` sobre cualquier rol
  - Acciones que permiten **deshabilitar CloudTrail** (borrar rastros)
- Uso de **políticas en línea** (en lugar de políticas gestionadas)

### 🌐 Acceso externo y movimiento lateral
- Roles cuya **trust policy permite ser asumidos desde cuentas externas** o desde Internet (`Principal: "*"` o `arn:aws:iam::[otra-cuenta]`)
- Hallazgos activos de **IAM Access Analyzer** (si está habilitado en tu cuenta)

---

## 📦 Requisitos

Antes de usar ScanFlaws, asegúrate de tener:

| Requisito | Detalle |
|---------|--------|
| **Python** | Versión 3.8 o superior |
| **Credenciales AWS** | Configuradas mediante `aws configure` o variables de entorno (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) |
| **Permisos mínimos en AWS** | El usuario o rol que ejecuta ScanFlaws debe tener permisos de **lectura en IAM** y (opcionalmente) en **Access Analyzer**. |



---

### ✅ ¿Qué mejora esta versión?

- **Bloque inicial en tabla**: el usuario entiende **al instante** qué hace, qué necesita y cómo instalarlo.
- **Secciones claras**: “Requisitos” y “Cómo instalar y usar” están bien separadas y con títulos explícitos.
- **Mantiene todo el contenido técnico** que ya tenías, pero mejor organizado.

---

Instalación y uso:

1) Clonar el repositorio R/:
   git clone https://github.com/DarkHama11/ScanFlaws.git
2) Entrar a la carpeta correcta R/:
   cd ScanFlaws\ScanFlaws
3) Instalar dependencias R/:
   pip install boto3 tabulate
4) Configurar credenciales AWS (solo la primera vez) R/:
   aws configure
5) Ejecutar el escáner R/:
   python main.py 

[*] Ejecutando checks de IAM...
[+] Escaneando IAM Access Analyzer en 17 regiones...

🛡️  Hallazgos en IAM:
| Check | Entidad | Detalle |
|-------|---------|---------|
| Usuarios sin MFA | haljr11 | MFA no habilitado |
|---------------------------------------------------------------------------------------------| 

### ✅ Permisos recomendados (policy mínima)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
