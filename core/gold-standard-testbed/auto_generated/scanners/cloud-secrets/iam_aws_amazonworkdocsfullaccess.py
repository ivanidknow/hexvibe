# Vulnerable: IAM-AWS-AmazonWorkDocsFullAccess
{
  "Action": [
    "workdocs:*",
    "ds:DescribeDirectories",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
