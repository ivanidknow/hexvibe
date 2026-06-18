# Vulnerable: IAM-AWS-AWSLambdaVPCAccessExecutionRole
{
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "ec2:CreateNetworkInterface",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSubnets",
...
  "Sid": "AWSLambdaVPCAccessExecutionPermissions"
}
