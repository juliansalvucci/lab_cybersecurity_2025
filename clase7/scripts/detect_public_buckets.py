#!/usr/bin/env python3
"""
CLASE 7 - SEGURIDAD EN LA NUBE Y VIRTUALIZACIÓN
Ejercicio 1: Detección de Buckets S3 Públicos
"""

import boto3
import sys
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
from datetime import datetime
import json
import argparse


class S3SecurityAuditor:
    """
    Auditor de seguridad para buckets S3 de AWS.
    Identifica configuraciones inseguras y genera reportes.
    """

    def __init__(self, profile_name=None, region=None, use_localstack=False):
        """
        Inicializa el auditor con credenciales de AWS o LocalStack.
        """
        try:
            if use_localstack:
                print("[+] Conectando a LocalStack...")

                self.s3 = boto3.client(
                    's3',
                    endpoint_url="http://localhost:4566",
                    aws_access_key_id="test",
                    aws_secret_access_key="test",
                    region_name=region or "us-east-1"
                )

            else:
                print("[+] Conectando a AWS...")
                if profile_name:
                    session = boto3.Session(profile_name=profile_name)
                    self.s3 = session.client('s3', region_name=region)
                else:
                    self.s3 = boto3.client('s3', region_name=region)

            print("[+] Conexión establecida correctamente")
            print(f"[+] Fecha de auditoría: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 70)

        except NoCredentialsError:
            print("[!] ERROR: No se encontraron credenciales de AWS")
            print("[!] Configure credenciales con 'aws configure'")
            sys.exit(1)

        except Exception as e:
            print(f"[!] ERROR al conectar: {str(e)}")
            sys.exit(1)

    def list_all_buckets(self):
        try:
            response = self.s3.list_buckets()
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            print(f"[+] Se encontraron {len(buckets)} buckets en la cuenta")
            return buckets
        except ClientError as e:
            print(f"[!] ERROR al listar buckets: {e}")
            return []

    def check_bucket_acl(self, bucket_name):
        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            public_permissions = []

            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')

                uri = grantee.get('URI', '')
                if uri in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    group_type = "AllUsers" if "AllUsers" in uri else "AuthenticatedUsers"
                    public_permissions.append({
                        'group': group_type,
                        'permission': permission
                    })

            return {
                'bucket': bucket_name,
                'is_public': len(public_permissions) > 0,
                'permissions': public_permissions
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                return {
                    'bucket': bucket_name,
                    'is_public': False,
                    'error': 'AccessDenied',
                    'permissions': []
                }
            else:
                print(f"[!] ERROR al verificar ACL de {bucket_name}: {e}")
                return {
                    'bucket': bucket_name,
                    'is_public': False,
                    'error': str(e),
                    'permissions': []
                }

    def check_bucket_policy(self, bucket_name):
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(policy['Policy'])

            has_public_policy = False
            public_statements = []

            for statement in policy_document.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')

                if (principal == '*' or
                        principal == {"AWS": "*"} or
                        principal.get('AWS') == '*'):

                    if effect == 'Allow':
                        has_public_policy = True
                        public_statements.append({
                            'effect': effect,
                            'actions': statement.get('Action', []),
                            'resources': statement.get('Resource', [])
                        })

            return {
                'has_policy': True,
                'is_public': has_public_policy,
                'statements': public_statements
            }

        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'NoSuchBucketPolicy':
                return {
                    'has_policy': False,
                    'is_public': False,
                    'statements': []
                }
            return {
                'has_policy': False,
                'is_public': False,
                'error': str(e),
                'statements': []
            }

    def check_public_access_block(self, bucket_name):
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            config = response.get('PublicAccessBlockConfiguration', {})

            return {
                'enabled': True,
                'block_public_acls': config.get('BlockPublicAcls', False),
                'ignore_public_acls': config.get('IgnorePublicAcls', False),
                'block_public_policy': config.get('BlockPublicPolicy', False),
                'restrict_public_buckets': config.get('RestrictPublicBuckets', False)
            }

        except ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'NoSuchPublicAccessBlockConfiguration':
                return {
                    'enabled': False,
                    'block_public_acls': False,
                    'ignore_public_acls': False,
                    'block_public_policy': False,
                    'restrict_public_buckets': False
                }
            return {
                'enabled': False,
                'error': str(e)
            }

    def audit_bucket(self, bucket_name, verbose=False):
        if verbose:
            print(f"\n[*] Auditando: {bucket_name}")

        acl_info = self.check_bucket_acl(bucket_name)
        policy_info = self.check_bucket_policy(bucket_name)
        block_info = self.check_public_access_block(bucket_name)

        is_public = acl_info['is_public'] or policy_info['is_public']

        if is_public and not block_info['enabled']:
            risk_level = "CRÍTICO"
        elif is_public:
            risk_level = "ALTO"
        elif not block_info['enabled']:
            risk_level = "MEDIO"
        else:
            risk_level = "BAJO"

        return {
            'bucket': bucket_name,
            'is_public': is_public,
            'risk_level': risk_level,
            'acl': acl_info,
            'policy': policy_info,
            'public_access_block': block_info
        }

    def audit_all_buckets(self, verbose=False):
        buckets = self.list_all_buckets()

        if not buckets:
            print("[!] No se encontraron buckets para auditar")
            return []

        print("\n[*] Iniciando auditoría de seguridad...")
        print("-" * 70)

        return [self.audit_bucket(b, verbose) for b in buckets]

    def print_summary(self, results):
        print("\n" + "=" * 70)
        print("RESUMEN DE AUDITORÍA DE SEGURIDAD S3")
        print("=" * 70)

        total_buckets = len(results)
        public_buckets = [r for r in results if r['is_public']]
        critical = [r for r in results if r['risk_level'] == 'CRÍTICO']
        high = [r for r in results if r['risk_level'] == 'ALTO']

        print(f"\n[+] Total de buckets analizados: {total_buckets}")
        print(f"[!] Buckets públicos encontrados: {len(public_buckets)}")
        print(f"[!] Buckets con riesgo CRÍTICO: {len(critical)}")
        print(f"[!] Buckets con riesgo ALTO: {len(high)}")

        if public_buckets:
            print("\n" + "-" * 70)
            print("BUCKETS PÚBLICOS DETECTADOS:")
            print("-" * 70)

            for result in public_buckets:
                print(f"\n[!] Bucket: {result['bucket']}")
                print(f"    Nivel de riesgo: {result['risk_level']}")

                for perm in result['acl']['permissions']:
                    print(f"      - {perm['group']}: {perm['permission']}")

                if result['policy']['is_public']:
                    for stmt in result['policy']['statements']:
                        print(f"      - Actions: {stmt['actions']}")

                if not result['public_access_block']['enabled']:
                    print("    [!] ADVERTENCIA: Bloqueo de acceso público NO configurado")

        print("\n" + "=" * 70)
        print("RECOMENDACIONES:")
        print("=" * 70)
        print("""
1. Revisar y eliminar permisos públicos innecesarios
2. Habilitar 'Block Public Access'
3. Implementar principio de mínimo privilegio
4. Activar cifrado SSE-S3 o SSE-KMS
5. Habilitar logging del bucket
6. Activar versionado
7. Usar AWS Config para monitoreo constante
        """)

    def export_to_json(self, results, filename='audit_results.json'):
        try:
            output = {
                'timestamp': datetime.now().isoformat(),
                'total_buckets': len(results),
                'public_buckets': len([r for r in results if r['is_public']]),
                'results': results
            }

            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)

            print(f"\n[+] Resultados exportados a: {filename}")

        except Exception as e:
            print(f"[!] ERROR al exportar resultados: {e}")


# -----------------------------------------
# PARSER (fuera de la clase)
# -----------------------------------------

parser = argparse.ArgumentParser(
    description="Auditor de seguridad S3 (AWS / LocalStack)"
)

parser.add_argument("--localstack", action="store_true", help="Usar LocalStack")
parser.add_argument("--profile", type=str, help="Perfil AWS CLI")
parser.add_argument("--region", type=str, default="us-east-1", help="Región AWS")

args = parser.parse_args()


def main():
    print("=" * 70)
    print("AUDITOR DE SEGURIDAD S3 - CLASE 7")
    print("UTN - Laboratorio de Ciberseguridad")
    print("=" * 70)

    auditor = S3SecurityAuditor(
        profile_name=args.profile,
        region=args.region,
        use_localstack=args.localstack
    )

    results = auditor.audit_all_buckets(verbose=False)

    auditor.print_summary(results)
    auditor.export_to_json(results)

    public_count = len([r for r in results if r['is_public']])
    sys.exit(1 if public_count > 0 else 0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Auditoría interrumpida por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] ERROR FATAL: {str(e)}")
        sys.exit(1)
