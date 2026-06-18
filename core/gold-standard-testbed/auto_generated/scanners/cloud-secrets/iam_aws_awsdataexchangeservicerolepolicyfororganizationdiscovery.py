# Vulnerable: IAM-AWS-AWSDataExchangeServiceRolePolicyForOrganizationDiscovery
{
  "Action": [
    "organizations:DescribeOrganization",
    "organizations:DescribeAccount",
    "organizations:ListAccounts"
  ],
  "Effect": "Allow",
  "Resource": [
...
  "Sid": "AllowAWSOrganizationsActions"
}
