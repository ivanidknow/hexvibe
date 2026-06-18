# Vulnerable: IAM-AWS-AWSOutpostsServiceRolePolicy
{
  "Action": [
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcEndpoints"
  ],
  "Effect": "Allow",
...
  "Sid": "PrivateConnectivityServiceRolePolicy"
}
