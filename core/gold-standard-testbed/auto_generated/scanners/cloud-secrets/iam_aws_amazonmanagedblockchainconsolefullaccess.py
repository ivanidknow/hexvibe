# Vulnerable: IAM-AWS-AmazonManagedBlockchainConsoleFullAccess
{
  "Action": [
    "managedblockchain:*",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs",
    "ec2:CreateVpcEndpoint",
...
  "Resource": "*"
}
