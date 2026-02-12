title: "Powermad Cheat Sheet"
description: "Herramientas para Machine Account Quota y explotación de DNS dinámico."
image: "/images/certs/ad-powermad.png"

# Powermad

**Powermad** es una colección de funciones para abusar de servicios como Machine Account Quota (agregar máquinas al dominio) y DNS dinámico. Es fundamental para ataques como **Resource-Based Constrained Delegation (RBCD)**.

[Repositorio Oficial](https://github.com/Kevin-Robertson/Powermad)

## Creación de Cuentas de Máquina

Por defecto, cualquier usuario validado en el dominio puede añadir hasta 10 computadoras al dominio (`ms-DS-MachineAccountQuota`). Esto es útil para obtener una cuenta con SPN y credenciales conocidas.

```powershell
# Importar el módulo
. .\Powermad.ps1

# Crear una nueva cuenta de máquina
New-MachineAccount -MachineAccount "FakePC" -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose
```

Una vez creada la máquina, tienes una cuenta válida en el dominio que controlas, lo cual puede usarse para diversos ataques de autenticación o para configurar RBCD.

## Uso en Resource-Based Constrained Delegation (RBCD)

RBCD permite configurar delegación en un objeto si tenemos permisos de escritura (`GenericWrite`, `GenericAll`, etc.) sobre ese objeto, sin necesidad de ser Domain Admin.

1.  **Crear Máquina Atacante**: Usamos Powermad para crear una cuenta que controlamos.
    `New-MachineAccount ...`
2.  **Preparar Descriptor de Seguridad**: Calculamos el SID de nuestra nueva máquina y creamos un descriptor que le permita "actuar en nombre de otros".
3.  **Aplicar Descriptor**: Escribimos este descriptor en el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` de la **máquina objetivo** (la víctima donde tenemos permisos de escritura).
4.  **Atacar**: Usamos Rubeus para solicitar un ticket desde nuestra máquina falsa hacia la víctima, impersonando a un Administrador.
