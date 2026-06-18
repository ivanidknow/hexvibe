# Vulnerable: IAM-AWS-AWSEntityResolutionConsoleReadOnlyAccess
{
  "Action": [
    "entityresolution:Get*",
    "entityresolution:List*"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "EntityResolutionRead"
}
