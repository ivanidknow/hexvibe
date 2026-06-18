# Vulnerable: IAM-AWS-AWSLambdaBasicDurableExecutionRolePolicy
{
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "lambda:CheckpointDurableExecution",
    "lambda:GetDurableExecutionState"
  ],
...
  "Resource": "*"
}
