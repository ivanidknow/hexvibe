# Vulnerable: IAM-AWS-ROSASharedVPCEndpointPolicy
{
  "Action": [
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeVpcs",
    "ec2:DescribeSecurityGroups"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "ReadPermissions"
}
