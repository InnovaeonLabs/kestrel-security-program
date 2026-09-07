#!/usr/bin/env bash
# Build the intentionally-vulnerable AWS footprint inside LocalStack.
# Prereqs: docker compose up (localstack), and `pip install awscli-local` (awslocal).
set -euo pipefail
echo "[*] Creating misconfigured resources in LocalStack..."
awslocal s3 mb s3://kestrel-statements-prod
awslocal secretsmanager create-secret --name prod/payments/signing-key \
  --secret-string '{"key":"lab-signing-key-not-real"}'
awslocal iam create-role --role-name kestrel-api-task \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
awslocal iam create-user --user-name svc_payouts
echo "[+] Setup complete."
