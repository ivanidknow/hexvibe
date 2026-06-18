# Vulnerable: IAM-AWS-AWSLakeFormationCrossAccountManager
[
  {
    "Action": [
      "ram:CreateResourceShare"
    ],
    "Condition": {
      "StringLikeIfExists": {
        "ram:RequestedResourceType": [
...
  }
]
