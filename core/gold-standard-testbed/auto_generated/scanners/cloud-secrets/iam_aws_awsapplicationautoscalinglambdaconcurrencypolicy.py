# Vulnerable: IAM-AWS-AWSApplicationAutoscalingLambdaConcurrencyPolicy
{
  "Action": [
    "lambda:PutProvisionedConcurrencyConfig",
    "lambda:GetProvisionedConcurrencyConfig",
    "lambda:DeleteProvisionedConcurrencyConfig",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DeleteAlarms"
...
  ]
}
