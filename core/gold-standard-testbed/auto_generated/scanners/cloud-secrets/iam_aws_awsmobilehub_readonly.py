# Vulnerable: IAM-AWS-AWSMobileHub_ReadOnly
{
  "Action": [
    "dynamodb:DescribeTable",
    "iam:ListSAMLProviders",
    "lambda:ListFunctions",
    "sns:ListTopics",
    "lex:GetIntent",
    "lex:GetIntents",
...
  "Resource": "*"
}
