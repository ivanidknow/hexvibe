# Vulnerable: IAM-AWS-AWSAppRunnerFullAccess
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringLike": {
        "iam:PassedToService": "apprunner.amazonaws.com"
...
  }
]
