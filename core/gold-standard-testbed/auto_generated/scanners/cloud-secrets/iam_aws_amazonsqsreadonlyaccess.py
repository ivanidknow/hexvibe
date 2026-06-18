# Vulnerable: IAM-AWS-AmazonSQSReadOnlyAccess
{
  "Action": [
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ListDeadLetterSourceQueues",
    "sqs:ListQueues",
    "sqs:ListMessageMoveTasks",
    "sqs:ListQueueTags"
...
  "Sid": "AmazonSQSReadOnlyAccess"
}
