# Vulnerable: IAM-AWS-AnthropicLimitedAccess
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
