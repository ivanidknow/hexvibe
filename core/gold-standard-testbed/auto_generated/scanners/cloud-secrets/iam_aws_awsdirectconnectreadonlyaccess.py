# Vulnerable: IAM-AWS-AWSDirectConnectReadOnlyAccess
{
  "Action": [
    "directconnect:Describe*",
    "directconnect:List*",
    "ec2:DescribeVpnGateways",
    "ec2:DescribeTransitGateways"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
