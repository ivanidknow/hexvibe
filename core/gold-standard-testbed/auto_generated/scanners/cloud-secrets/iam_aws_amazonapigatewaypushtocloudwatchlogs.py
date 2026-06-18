# Vulnerable: IAM-AWS-AmazonAPIGatewayPushToCloudWatchLogs
{
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:PutLogEvents",
    "logs:GetLogEvents",
...
  "Resource": "*"
}
