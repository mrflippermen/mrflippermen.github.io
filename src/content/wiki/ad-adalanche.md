---
title: "Adalanche Cheat Sheet"
category: "AD"
description: "Herramienta de análisis visual de ACLs y permisos en Active Directory."
image: "/images/wiki/11.png"
---

# Adalanche: Visualización de Permisos y ACLs

**Adalanche** es una herramienta open-source para visualizar y analizar permisos en Active Directory. Es similar a BloodHound en su objetivo de mapear relaciones, pero se enfoca mucho en la visualización inmediata de ACLs y permisos efectivos.

[Repositorio Oficial](https://github.com/lkarlslund/adalanche)

## Recolección y Análisis

Adalanche combina la recolección y el análisis en un solo binario.

### Recolección Remota (Remote Collect)

```bash
# Formato básico desde Linux/Mac/Windows
./adalanche collect activedirectory --domain <Domain> --username <User> --password <Pass> --server <DC_IP>

# Ejemplo
./adalanche collect activedirectory --domain windcorp.local --username pepe@windcorp.local --password 'password123' --server dc01.windcorp.local
```

### Solución de Problemas de Conexión

*   **Error de Certificado (LDAP SSL/TLS)**: Si falla por certificados auto-firmados o desconocidos.
    Añade: `--tlsmode NoTLS --port 389`
*   **Problemas de Autenticación**:
    Añade: `--authmode basic`

### Análisis Visual

Una vez recolectados los datos, Adalanche inicia un servidor web local para explorar el grafo.

```bash
./adalanche analyze
# Abre tu navegador en http://127.0.0.1:8080
```

En la interfaz puedes buscar usuarios o grupos y ver gráficamente quién tiene control sobre qué (quién puede resetear contraseñas de quién, quién es admin de qué máquina, etc.).
