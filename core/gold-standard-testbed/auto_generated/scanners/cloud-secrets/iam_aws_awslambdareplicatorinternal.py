# Vulnerable: IAM-AWS-AWSLambdaReplicatorInternal
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringLikeIfExists": {
        "iam:PassedToService": [
...
  }
]
