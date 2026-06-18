# Vulnerable: IAM-AWS-BedrockAgentCoreNetworkServiceRolePolicy
{
  "Action": [
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs"
  ],
  "Effect": "Allow",
...
  "Sid": "AllowDescribeNetworkingResources"
}
