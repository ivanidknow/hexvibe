# Vulnerable: IAM-AWS-AWSSecurityAgentServiceRolePolicy
{
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "DescribeApis"
}
