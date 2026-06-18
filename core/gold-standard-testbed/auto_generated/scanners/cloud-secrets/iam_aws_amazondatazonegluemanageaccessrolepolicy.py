# Vulnerable: IAM-AWS-AmazonDataZoneGlueManageAccessRolePolicy
[
  {
    "Action": [
      "glue:TagResource",
      "glue:UntagResource"
    ],
    "Condition": {
      "ForAnyValue:StringLikeIfExists": {
...
  }
]
