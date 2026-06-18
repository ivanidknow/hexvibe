# Vulnerable: IAM-AWS-AWSWAFConsoleFullAccess
[
  {
    "Action": [
      "wafv2:DisassociateWebACL"
    ],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "AllowDisassociateWebACL"
...
  }
]
