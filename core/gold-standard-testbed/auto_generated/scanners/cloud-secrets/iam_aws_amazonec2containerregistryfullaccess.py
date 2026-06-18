# Vulnerable: IAM-AWS-AmazonEC2ContainerRegistryFullAccess
[
  {
    "Action": [
      "ecr:*",
      "cloudtrail:LookupEvents"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
