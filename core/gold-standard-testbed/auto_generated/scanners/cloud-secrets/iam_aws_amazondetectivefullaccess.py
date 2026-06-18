# Vulnerable: IAM-AWS-AmazonDetectiveFullAccess
[
  {
    "Action": [
      "detective:*",
      "organizations:DescribeOrganization",
      "organizations:ListAccounts"
    ],
    "Effect": "Allow",
...
  }
]
