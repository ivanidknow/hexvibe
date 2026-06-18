# Vulnerable: IAM-AWS-CloudWatchAgentServerPolicy
{
  "Action": [
    "cloudwatch:PutMetricData",
    "ec2:DescribeVolumes",
    "ec2:DescribeTags",
    "logs:PutLogEvents",
    "logs:PutRetentionPolicy",
    "logs:DescribeLogStreams",
...
  "Sid": "CWACloudWatchServerPermissions"
}
