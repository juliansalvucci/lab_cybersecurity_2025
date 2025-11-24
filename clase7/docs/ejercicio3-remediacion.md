# EJERCICIO 3 - REMEDIACIÓN DE VULNERABILIDAD

## 1. Vulnerabilidad Identificada

-   **Bucket:** `bucket-vulnerable-lab-1763949663`

-   **Problema:** Acceso público de **lectura y escritura** mediante
    ACLs.

-   **Riesgo:** **CRÍTICO**

-   **Evidencia:**\
    El bucket permitía acceso total al público. En la ACL se observaron
    permisos:

        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        },
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "WRITE"
        }

## 2. Detección

-   **Herramienta utilizada:** `detect_public_buckets.py`

-   **Hallazgos:**\
    El script identificó que el bucket era **público**, con permisos
    READ y WRITE asignados a AllUsers.

-   **Salida del script:**

        [!] Bucket bucket-vulnerable-lab-1763949663 es PÚBLICO
        Permisos detectados:
        - AllUsers: READ
        - AllUsers: WRITE

## 3. Remediación Aplicada

### 3.1 ACL Privada

``` bash
aws $LS s3api put-bucket-acl   --bucket bucket-vulnerable-lab-1763949663   --acl private
```

### 3.2 PublicAccessBlock

``` bash
aws $LS s3api put-public-access-block   --bucket bucket-vulnerable-lab-1763949663   --public-access-block-configuration   BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 3.3 Verificación PublicAccessBlock

``` bash
aws $LS s3api get-public-access-block --bucket bucket-vulnerable-lab-1763949663
```

### 3.4 Verificación final ACLs

``` bash
aws $LS s3api get-bucket-acl --bucket bucket-vulnerable-lab-1763949663
```
