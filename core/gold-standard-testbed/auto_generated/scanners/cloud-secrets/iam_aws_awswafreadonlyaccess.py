# Vulnerable: IAM-AWS-AWSWAFReadOnlyAccess
[
  {
    "Action": [
      "cognito-idp:ListResourcesForWebACL"
    ],
    "Effect": "Allow",
    "Resource": "*",
    "Sid": "AllowListActionsForCognito"
...
  }
]
