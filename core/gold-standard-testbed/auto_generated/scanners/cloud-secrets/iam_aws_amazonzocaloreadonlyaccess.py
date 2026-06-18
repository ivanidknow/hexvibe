# Vulnerable: IAM-AWS-AmazonZocaloReadOnlyAccess
{
  "Action": [
    "zocalo:Describe*",
    "ds:DescribeDirectories",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
