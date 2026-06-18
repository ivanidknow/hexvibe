# Vulnerable: IAM-AWS-AWSConfigRoleForOrganizations
{
  "Action": [
    "organizations:ListAccounts",
    "organizations:DescribeOrganization",
    "organizations:ListAWSServiceAccessForOrganization",
    "organizations:ListDelegatedAdministrators"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
