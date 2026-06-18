# Vulnerable: IAM-AWS-PowerUserAccess
[
  {
    "Effect": "Allow",
    "NotAction": [
      "iam:*",
      "organizations:*",
      "account:*"
    ],
...
  }
]
