# Vulnerable: IAM-AWS-AWSSecurityIncidentResponseServiceRolePolicy
{
  "Action": [
    "organizations:ListAccounts",
    "organizations:ListChildren",
    "organizations:DescribeAccount",
    "organizations:ListDelegatedAdministrators"
  ],
  "Effect": "Allow",
...
  "Sid": "SecurityIncidentResponseOrganizationsPolicy"
}
