# Vulnerable: IAM-AWS-AWSLambdaDynamoDBExecutionRole
{
  "Action": [
    "dynamodb:DescribeStream",
    "dynamodb:GetRecords",
    "dynamodb:GetShardIterator",
    "dynamodb:ListStreams",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
...
  "Resource": "*"
}
