# Vulnerable: IAM-AWS-AWSTrustedAdvisorReportingServiceRolePolicy
{
  "Action": [
    "organizations:DescribeOrganization",
    "organizations:ListAWSServiceAccessForOrganization",
    "organizations:ListAccounts",
    "organizations:ListAccountsForParent",
    "organizations:ListDelegatedAdministrators",
    "organizations:ListOrganizationalUnitsForParent",
...
  "Resource": "*"
}
