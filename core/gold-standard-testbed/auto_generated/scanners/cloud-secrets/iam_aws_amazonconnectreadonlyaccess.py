# Vulnerable: IAM-AWS-AmazonConnectReadOnlyAccess
{
  "Action": [
    "connect:Get*",
    "connect:Describe*",
    "connect:List*",
    "ds:DescribeDirectories"
  ],
  "Effect": "Allow",
...
  "Sid": "AllowConnectReadOnly"
}
