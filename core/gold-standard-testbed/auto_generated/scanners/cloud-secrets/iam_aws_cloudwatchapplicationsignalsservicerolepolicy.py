# Vulnerable: IAM-AWS-CloudWatchApplicationSignalsServiceRolePolicy
[
  {
    "Action": [
      "xray:GetServiceGraph"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
