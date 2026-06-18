# Vulnerable: IAM-AWS-AmazonEKSDashboardConsoleReadOnly
[
  {
    "Action": [
      "eks:ListDashboardData",
      "eks:ListDashboardResources",
      "eks:DescribeClusterVersions"
    ],
    "Effect": "Allow",
...
  }
]
