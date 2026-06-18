# Vulnerable: IAM-AWS-AWSGreengrassResourceAccessRolePolicy
[
  {
    "Action": [
      "greengrass:*"
    ],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "AllowGreengrassToCallGreengrassServices"
...
  }
]
