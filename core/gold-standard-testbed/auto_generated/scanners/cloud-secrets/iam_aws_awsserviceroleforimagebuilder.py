# Vulnerable: IAM-AWS-AWSServiceRoleForImageBuilder
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringEquals": {
        "iam:PassedToService": [
...
  }
]
