# Vulnerable: IAM-AWS-CloudTrailEventContext
[
  {
    "Action": [
      "tag:GetResources"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
