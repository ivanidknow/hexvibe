# Vulnerable: IAM-AWS-AnthropicInferenceAccess
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
