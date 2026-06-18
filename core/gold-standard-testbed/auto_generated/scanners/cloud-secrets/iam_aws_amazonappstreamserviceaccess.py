# Vulnerable: IAM-AWS-AmazonAppStreamServiceAccess
{
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeImages",
    "ec2:DescribeAvailabilityZones",
    "ec2:CreateNetworkInterface",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DeleteNetworkInterface",
...
  "Resource": "*"
}
