# Vulnerable: IAM-AWS-S3StorageLensServiceRolePolicy
{
  "Action": [
    "organizations:DescribeOrganization",
    "organizations:ListAccounts",
    "organizations:ListAWSServiceAccessForOrganization",
    "organizations:ListDelegatedAdministrators"
  ],
  "Effect": "Allow",
...
  "Sid": "AwsOrgsAccess"
}
