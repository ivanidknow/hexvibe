# Vulnerable: IAM-AWS-AWSBatchFullAccess
{
  "Action": [
    "batch:*",
    "cloudwatch:GetMetricStatistics",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeKeyPairs",
    "ec2:DescribeVpcs",
...
  "Resource": "*"
}
