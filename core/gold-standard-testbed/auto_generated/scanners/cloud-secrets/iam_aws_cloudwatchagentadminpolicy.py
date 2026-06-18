# Vulnerable: IAM-AWS-CloudWatchAgentAdminPolicy
{
  "Action": [
    "cloudwatch:PutMetricData",
    "ec2:DescribeTags",
    "logs:PutLogEvents",
    "logs:PutRetentionPolicy",
    "logs:DescribeLogStreams",
    "logs:DescribeLogGroups",
...
  "Sid": "CWACloudWatchPermissions"
}
