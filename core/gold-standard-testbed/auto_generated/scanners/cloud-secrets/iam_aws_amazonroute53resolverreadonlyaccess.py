# Vulnerable: IAM-AWS-AmazonRoute53ResolverReadOnlyAccess
{
  "Action": [
    "route53resolver:Get*",
    "route53resolver:List*",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets"
...
  "Sid": "AmazonRoute53ResolverReadOnlyAccess"
}
