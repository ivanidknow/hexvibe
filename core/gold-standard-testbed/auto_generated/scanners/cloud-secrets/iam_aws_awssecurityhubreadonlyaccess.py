# Vulnerable: IAM-AWS-AWSSecurityHubReadOnlyAccess
{
  "Action": [
    "securityhub:Get*",
    "securityhub:List*",
    "securityhub:BatchGet*",
    "securityhub:Describe*"
  ],
  "Effect": "Allow",
...
  "Sid": "AWSSecurityHubReadOnlyAccess"
}
