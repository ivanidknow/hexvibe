# Vulnerable: IAM-AWS-AWSApplicationAutoScalingCustomResourcePolicy
{
  "Action": [
    "execute-api:Invoke",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DeleteAlarms"
  ],
  "Effect": "Allow",
...
  ]
}
