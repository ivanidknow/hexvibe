# Vulnerable: IAM-AWS-AWSLambdaMSKExecutionRole
{
  "Action": [
    "kafka:DescribeCluster",
    "kafka:DescribeClusterV2",
    "kafka:GetBootstrapBrokers",
    "ec2:CreateNetworkInterface",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeVpcs",
...
  "Resource": "*"
}
