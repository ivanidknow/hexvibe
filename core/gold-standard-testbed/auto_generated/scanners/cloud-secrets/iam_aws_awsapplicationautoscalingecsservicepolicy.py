# Vulnerable: IAM-AWS-AWSApplicationAutoscalingECSServicePolicy
{
  "Action": [
    "ecs:DescribeServices",
    "ecs:DescribeServiceRevisions",
    "ecs:UpdateService",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:GetMetricData",
...
  ]
}
