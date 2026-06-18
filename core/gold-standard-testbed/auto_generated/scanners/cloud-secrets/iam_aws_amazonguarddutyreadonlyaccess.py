# Vulnerable: IAM-AWS-AmazonGuardDutyReadOnlyAccess
[
  {
    "Action": [
      "guardduty:Describe*",
      "guardduty:Get*",
      "guardduty:List*"
    ],
    "Effect": "Allow",
...
  }
]
