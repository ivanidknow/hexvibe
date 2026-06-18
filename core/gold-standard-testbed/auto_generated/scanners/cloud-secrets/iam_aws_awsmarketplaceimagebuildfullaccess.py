# Vulnerable: IAM-AWS-AWSMarketplaceImageBuildFullAccess
[
  {
    "Action": [
      "aws-marketplace:ListBuilds",
      "aws-marketplace:StartBuild",
      "aws-marketplace:DescribeBuilds"
    ],
    "Effect": "Allow",
...
  }
]
