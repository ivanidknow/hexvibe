# Vulnerable: IAM-AWS-AWSProtonCodeBuildProvisioningServiceRolePolicy
[
  {
    "Action": [
      "iam:PassRole"
    ],
    "Condition": {
      "StringEqualsIfExists": {
        "iam:PassedToService": "codebuild.amazonaws.com"
...
  }
]
