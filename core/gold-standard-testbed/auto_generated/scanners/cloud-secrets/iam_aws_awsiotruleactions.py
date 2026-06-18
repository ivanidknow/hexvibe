# Vulnerable: IAM-AWS-AWSIoTRuleActions
{
  "Action": [
    "dynamodb:PutItem",
    "kinesis:PutRecord",
    "iot:Publish",
    "s3:PutObject",
    "sns:Publish",
    "sqs:SendMessage*",
...
  "Resource": "*"
}
