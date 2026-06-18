# Vulnerable: IAM-AWS-AmazonMQApiReadOnlyAccess
{
  "Action": [
    "mq:Describe*",
    "mq:List*",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs"
...
  "Resource": "*"
}
