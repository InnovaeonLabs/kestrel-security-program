# Kestrel Pay - production AWS footprint (Terraform, lab).
# INTENTIONAL misconfigurations are present so the IaC scanner (Checkov) has real
# findings; the remediated versions are in hardened.tf.example. Never `apply` this.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# --- Statements bucket: MISCONFIGURED (public, unencrypted, no logging/versioning) ---
resource "aws_s3_bucket" "statements" {
  bucket = "kestrel-statements-prod"
}

resource "aws_s3_bucket_public_access_block" "statements" {
  bucket                  = aws_s3_bucket.statements.id
  block_public_acls       = false # CKV_AWS_53: should be true
  block_public_policy     = false # CKV_AWS_54: should be true
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "statements_public" {
  bucket = aws_s3_bucket.statements.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.statements.arn}/*"
    }]
  })
}

# --- API task role: OVER-PRIVILEGED (wildcard admin) ---
resource "aws_iam_role" "api_task" {
  name = "kestrel-api-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "api_task_admin" {
  name = "api-task-inline"
  role = aws_iam_role.api_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*" # CKV_AWS_63: wildcard action
      Resource = "*" # wildcard resource
    }]
  })
}

# --- Security group: OPEN to the world on all ports ---
resource "aws_security_group" "api" {
  name = "kestrel-api-sg"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # CKV_AWS_24: open ingress
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Secret: signing key, but NO rotation configured ---
resource "aws_secretsmanager_secret" "signing_key" {
  name = "prod/payments/signing-key" # CKV_AWS_149/304: no rotation
}

# --- RDS: publicly accessible, unencrypted, hardcoded password (BAD) ---
resource "aws_db_instance" "ledger" {
  identifier          = "kestrel-ledger"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "kestrel"
  password            = "changeme-lab-only" # CKV_SECRET / hardcoded credential
  publicly_accessible = true                # CKV_AWS_17
  storage_encrypted   = false               # CKV_AWS_16
  skip_final_snapshot = true
}
