# Vulnerable: IAM-AWS-AWSTransferConsoleFullAccess
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringEquals": {
        "iam:PassedToService": "transfer.amazonaws.com"
...
  }
]
