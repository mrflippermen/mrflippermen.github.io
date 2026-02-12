---
title: "BloodHound Cheat Sheet"
description: "Mapeo de relaciones de confianza y caminos de ataque en Active Directory."
---

# BloodHound

**BloodHound** utiliza teoría de grafos para revelar las relaciones ocultas y, a menudo, no deseadas dentro de un entorno de Active Directory. Puede identificar rutas de ataque complejas que serían imposibles de ver manualmente.

[Repositorio Oficial](https://github.com/BloodHoundAD/BloodHound)

## Recolección de Datos (Ingestion)

Para que BloodHound funcione, primero debes recolectar información del dominio usando un "Ingestor".

### SharpHound (Desde Windows)
Es el recolector oficial en C#/.NET. Se puede ejecutar como ejecutable o script de PowerShell.

```powershell
# Versión EXE
.\SharpHound.exe --CollectionMethod All --Domain <Domain> --ZipFileName data.zip

# Versión PowerShell
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory .
```
*   `--CollectionMethod All`: Recolecta grupos, sesiones locales, confianzas, ACLs, etc.
*   `--Stealth`: Opción para realizar consultas más lentas y discretas.

### BloodHound-Python (Desde Linux/Remoto)
Ideal si no tienes acceso directo a una máquina Windows unida al dominio pero tienes credenciales.

[Repositorio Python](https://github.com/fox-it/BloodHound.py)

```bash
# Instalación
pip3 install bloodhound

# Ejecución
bloodhound-python -u <Usuario> -p <Password> -ns <IP_DC> -d <Dominio> -c All
```
Esto generará varios archivos JSON que puedes arrastrar a la interfaz de BloodHound.

## Análisis (La Interfaz)

Una vez importados los datos, usa las consultas predefinidas o crea las tuyas:

*   **Find Shortest Paths to Domain Admins**: Muestra la ruta más rápida para ser DA.
*   **Find Principals with DCSync Rights**: Muestra quién puede hacer DCSync (y robar credenciales sin loguearse).
*   **Kerberoasting**: Muestra usuarios con SPN (Kerberoastables).
*   **AS-REP Roasting**: Muestra usuarios vulnerables a AS-REP Roasting.

## Camino Típico de Ataque

1.  **Ingreso**: Tienes un usuario raso.
2.  **BloodHound**: Descubres que tu usuario es Admin Local en `PC-FINANZAS`.
3.  **BloodHound**: Ves que en `PC-FINANZAS` hay una sesión activa de `MANAGER-01`.
4.  **BloodHound**: Ves que `MANAGER-01` es miembro del grupo `IT-SUPPORT`.
5.  **BloodHound**: Ves que `IT-SUPPORT` tiene permisos de `GenericWrite` sobre el Controlador de Dominio.
6.  **Ataque**: Ejecutas esta cadena para comprometer el dominio.
