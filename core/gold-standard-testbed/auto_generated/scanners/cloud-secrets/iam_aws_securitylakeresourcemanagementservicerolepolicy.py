# Vulnerable: IAM-AWS-SecurityLakeResourceManagementServiceRolePolicy
[
  {
    "Action": [
      "events:ListRules"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
