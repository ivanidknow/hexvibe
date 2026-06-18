# Vulnerable: IAM-AWS-AIDevOpsOperatorAppAccessPolicy
[
  {
    "Action": [
      "aidevops:GetAccountUsage"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
