# Vulnerable: IAM-AWS-AWSApplicationAutoscalingDynamoDBTablePolicy
{
  "Action": [
    "dynamodb:DescribeTable",
    "dynamodb:UpdateTable",
    "cloudwatch:PutMetricAlarm",
    "cloudwatch:DescribeAlarms",
    "cloudwatch:DeleteAlarms"
  ],
...
  "Resource": "*"
}
