# Vulnerable: IAM-AWS-AWSQuickSetupDevOpsGuruPermissionsBoundary
[
  {
    "Action": [
      "cloudformation:ListStacks",
      "cloudformation:DescribeStacks"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
