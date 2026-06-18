# Vulnerable: IAM-AWS-AWSSSMOpsInsightsServiceRolePolicy
[
  {
    "Action": [
      "ssm:CreateOpsItem",
      "ssm:AddTagsToResource"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
