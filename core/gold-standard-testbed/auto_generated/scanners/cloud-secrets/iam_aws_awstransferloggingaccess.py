# Vulnerable: IAM-AWS-AWSTransferLoggingAccess
{
  "Action": [
    "logs:CreateLogStream",
    "logs:DescribeLogStreams",
    "logs:CreateLogGroup",
    "logs:PutLogEvents"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
