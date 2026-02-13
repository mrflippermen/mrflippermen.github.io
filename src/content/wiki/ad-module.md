---
title: "Active Directory PowerShell Module Cheat Sheet"
description: "Uso del módulo oficial de Microsoft para enumeración sigilosa (Living off the Land)."
image: "/images/wiki/9.png"
---

# Active Directory Module (AD Module)

El **Módulo de Active Directory para Windows PowerShell** es la herramienta oficial de Microsoft. Es excelente para la enumeración porque está firmada por Microsoft y su uso es "esperado" en entornos corporativos, lo que reduce la probabilidad de detección por antivirus/EDR comparado con herramientas ofensivas como PowerView.

[Repositorio (DLL Independiente)](https://github.com/samratashok/ADModule) - Si no está instalado en la máquina, puedes importar la DLL.

## Información de Dominio y Bosque

*   **Dominio Actual**: `Get-ADDomain`
*   **Otro Dominio**: `Get-ADDomain -Identity <Domain>`
*   **SID del Dominio**: `(Get-ADDomain).DomainSID`
*   **Controladores de Dominio**:
    `Get-ADDomainController`
*   **Relaciones de Confianza (Trusts)**:
    `Get-ADTrust -Filter *`
*   **Bosque (Forest)**:
    `Get-ADForest`
    `(Get-ADForest).Domains` (Listar dominios del bosque).

## Usuarios y Grupos

*   **Obtener Usuario**:
    `Get-ADUser -Filter * -Identity <User> -Properties *`
*   **Búsqueda por Atributo (Description)**:
    Muy útil para buscar contraseñas escritas en descripciones.
    `Get-ADUser -Filter 'Description -like "*pass*"' -Properties Description | select Name, Description`
*   **Usuarios Kerberoastables (SPN)**:
    `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
*   **Usuarios AS-REP Roastables (No PreAuth)**:
    `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`
*   **Grupos**:
    `Get-ADGroup -Filter *`
*   **Miembros de Grupo**:
    `Get-ADGroupMember -Identity "Domain Admins"`

## Computadoras

*   **Listar Computadoras**:
    `Get-ADComputer -Filter * -Properties *`
*   **Computadoras con Delegación**:
    `Get-ADComputer -Filter {TrustedForDelegation -eq $True}`

## Políticas

*   **AppLocker Efectivo**:
    `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

## Modificación y Ataque (Si se tienen permisos)

*   **Agregar SPN a un usuario** (Targeted Kerberoasting):
    `Set-ADUser -Identity <User> -ServicePrincipalNames @{Add='ops/backdoor'}`
*   **Deshabilitar Pre-Auth Kerberos**:
    `Set-ADAccountControl -Identity <User> -DoesNotRequirePreAuth $true`
