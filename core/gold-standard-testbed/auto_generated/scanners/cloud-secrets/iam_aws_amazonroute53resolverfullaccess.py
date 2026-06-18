# Vulnerable: IAM-AWS-AmazonRoute53ResolverFullAccess
{
  "Action": [
    "route53resolver:*",
    "ec2:DescribeSubnets",
    "ec2:CreateNetworkInterface",
    "ec2:DeleteNetworkInterface",
    "ec2:ModifyNetworkInterfaceAttribute",
    "ec2:DescribeNetworkInterfaces",
...
  "Sid": "AmazonRoute53ResolverFullAccess"
}
