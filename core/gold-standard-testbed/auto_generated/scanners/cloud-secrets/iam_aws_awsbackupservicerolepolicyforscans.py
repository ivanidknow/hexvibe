# Vulnerable: IAM-AWS-AWSBackupServiceRolePolicyForScans
[
  {
    "Action": [
      "guardduty:StartMalwareScan",
      "guardduty:GetMalwareScan"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
