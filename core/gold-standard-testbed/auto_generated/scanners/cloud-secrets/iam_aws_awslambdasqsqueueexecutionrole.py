# Vulnerable: IAM-AWS-AWSLambdaSQSQueueExecutionRole
{
  "Action": [
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
    "sqs:GetQueueAttributes",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
...
  "Resource": "*"
}
