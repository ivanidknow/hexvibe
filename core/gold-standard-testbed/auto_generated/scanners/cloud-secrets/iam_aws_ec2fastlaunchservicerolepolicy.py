# Vulnerable: IAM-AWS-EC2FastLaunchServiceRolePolicy
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
