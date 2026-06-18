# Vulnerable: IAM-AWS-AWSApplicationAutoscalingCassandraTablePolicy
{
  "Action": [
    "cassandra:Alter",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DeleteAlarms"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
