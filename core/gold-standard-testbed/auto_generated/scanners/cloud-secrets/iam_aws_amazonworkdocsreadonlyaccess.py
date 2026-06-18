# Vulnerable: IAM-AWS-AmazonWorkDocsReadOnlyAccess
{
  "Action": [
    "workdocs:Describe*",
    "ds:DescribeDirectories",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
