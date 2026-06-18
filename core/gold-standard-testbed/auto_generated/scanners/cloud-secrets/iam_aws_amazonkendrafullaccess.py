# Vulnerable: IAM-AWS-AmazonKendraFullAccess
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringEquals": {
        "iam:PassedToService": "kendra.amazonaws.com"
...
  }
]
