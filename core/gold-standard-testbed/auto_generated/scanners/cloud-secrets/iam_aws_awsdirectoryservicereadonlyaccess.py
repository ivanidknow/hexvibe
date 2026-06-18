# Vulnerable: IAM-AWS-AWSDirectoryServiceReadOnlyAccess
{
  "Action": [
    "ds:Check*",
    "ds:Describe*",
    "ds:Get*",
    "ds:List*",
    "ds:Verify*",
    "ec2:DescribeNetworkInterfaces",
...
  "Resource": "*"
}
