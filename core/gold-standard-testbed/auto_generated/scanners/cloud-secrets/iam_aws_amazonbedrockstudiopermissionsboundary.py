# Vulnerable: IAM-AWS-AmazonBedrockStudioPermissionsBoundary
[
  {
    "Action": [
      "aoss:APIAccessAll"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
