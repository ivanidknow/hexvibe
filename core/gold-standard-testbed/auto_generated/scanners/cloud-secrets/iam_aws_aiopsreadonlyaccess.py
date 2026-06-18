# Vulnerable: IAM-AWS-AIOpsReadOnlyAccess
[
  {
    "Action": [
      "aiops:Get*",
      "aiops:List*",
      "aiops:ValidateInvestigationGroup"
    ],
    "Effect": "Allow",
...
  }
]
