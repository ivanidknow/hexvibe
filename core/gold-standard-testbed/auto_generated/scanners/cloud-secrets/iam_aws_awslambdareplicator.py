# Vulnerable: IAM-AWS-AWSLambdaReplicator
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringLikeIfExists": {
        "iam:PassedToService": "lambda.amazonaws.com"
...
  }
]
