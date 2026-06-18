# Vulnerable: IAM-AWS-AWSWAFConsoleReadOnlyAccess
[
  {
    "Action": [
      "ec2:DescribeRegions"
    ],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "AllowEC2DescribeRegions"
...
  }
]
