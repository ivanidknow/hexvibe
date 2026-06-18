# Vulnerable: IAM-AWS-AnthropicReadOnlyAccess
[
  {
    "Action": [
      "aws-external-anthropic:GetAccountStatus",
      "aws-external-anthropic:CallWithBearerToken"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
