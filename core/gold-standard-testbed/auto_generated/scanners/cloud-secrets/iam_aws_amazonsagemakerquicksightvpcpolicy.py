# Vulnerable: IAM-AWS-AmazonSageMakerQuickSightVPCPolicy
{
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeRouteTables"
...
  "Sid": "DescribeQuickSightVPCConnectionEC2Resources"
}
