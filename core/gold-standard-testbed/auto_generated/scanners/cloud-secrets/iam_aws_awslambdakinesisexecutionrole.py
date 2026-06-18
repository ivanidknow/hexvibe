# Vulnerable: IAM-AWS-AWSLambdaKinesisExecutionRole
{
  "Action": [
    "kinesis:DescribeStream",
    "kinesis:DescribeStreamSummary",
    "kinesis:GetRecords",
    "kinesis:GetShardIterator",
    "kinesis:ListShards",
    "kinesis:ListStreams",
...
  "Resource": "*"
}
