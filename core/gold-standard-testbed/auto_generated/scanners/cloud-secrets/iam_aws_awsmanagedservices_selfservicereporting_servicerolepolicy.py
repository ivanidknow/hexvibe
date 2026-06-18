# Vulnerable: IAM-AWS-AWSManagedServices_SelfServiceReporting_ServiceRolePolicy
{
  "Action": [
    "organizations:DescribeOrganization",
    "organizations:ListAWSServiceAccessForOrganization",
    "organizations:ListDelegatedAdministrators",
    "organizations:DescribeAccount",
    "organizations:ListAccounts"
  ],
...
  "Resource": "*"
}
