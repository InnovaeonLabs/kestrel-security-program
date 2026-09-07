"""Confirm the live LocalStack misconfig + emit normalized telemetry the detections consume.

Queries LocalStack (boto3 -> http://localhost:4566) for the post-attack state and writes
CloudTrail-shaped events into the range telemetry so KP-0030/0031/0032 fire on LIVE data.
Prereqs: `pip install boto3`, LocalStack up, setup.sh + attack.sh run.
Usage: python collect.py   then   python ../../automation/normalize/normalize.py && ... run_sigma.py
"""
from __future__ import annotations
import json, os, boto3
ENDPOINT = os.environ.get("LOCALSTACK_URL", "http://localhost:4566")
OUT = os.path.join(os.path.dirname(__file__), "..", "..", "automation", "normalize", "samples", "cloudtrail-localstack.json")
s = boto3.client("iam", endpoint_url=ENDPOINT, aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")
s3 = boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1")
records = []
# confirm the admin escalation happened
for p in s.list_attached_user_policies(UserName="svc_payouts").get("AttachedPolicies", []):
    records.append({"eventTime": "2026-08-21T14:12:00Z", "eventName": "AttachUserPolicy",
                    "eventSource": "iam.amazonaws.com", "sourceIPAddress": "45.77.0.10",
                    "userIdentity": {"arn": "arn:aws:sts::000000000000:assumed-role/kestrel-api-task/s", "type": "AssumedRole"},
                    "requestParameters": {"userName": "svc_payouts", "policyArn": p["PolicyArn"]}})
# confirm the public bucket policy
try:
    pol = s3.get_bucket_policy(Bucket="kestrel-statements-prod")["Policy"]
    if '"*"' in pol:
        records.append({"eventTime": "2026-08-21T14:12:40Z", "eventName": "PutBucketPolicy",
                        "eventSource": "s3.amazonaws.com", "sourceIPAddress": "45.77.0.10",
                        "userIdentity": {"arn": "arn:aws:sts::000000000000:assumed-role/kestrel-api-task/s", "type": "AssumedRole"},
                        "requestParameters": {"bucketName": "kestrel-statements-prod", "bucketPolicy": json.loads(pol)}})
except Exception as e:
    print("no bucket policy:", e)
json.dump({"Records": records}, open(OUT, "w"), indent=2)
print(f"confirmed {len(records)} misconfig(s) live in LocalStack -> {OUT}")
