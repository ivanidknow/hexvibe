# Vulnerable: IAM-AWS-AmazonFSxConsoleReadOnlyAccess
{
  "Action": [
    "cloudwatch:DescribeAlarms",
    "cloudwatch:GetMetricData",
    "ds:DescribeDirectories",
    "ec2:DescribeNetworkInterfaceAttribute",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
...
  "Sid": "FSxReadOnlyPermissions"
}
