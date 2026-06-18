# Vulnerable: IAM-AWS-AlexaForBusinessGatewayExecution
{
  "Action": [
    "a4b:List*",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:DescribeLogGroups",
    "logs:PutLogEvents"
  ],
...
  "Resource": "*"
}
