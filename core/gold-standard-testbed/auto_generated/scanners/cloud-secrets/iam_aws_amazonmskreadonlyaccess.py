# Vulnerable: IAM-AWS-AmazonMSKReadOnlyAccess
{
  "Action": [
    "kafka:Describe*",
    "kafka:List*",
    "kafka:Get*",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
...
  "Resource": "*"
}
