# Vulnerable: IAM-AWS-AWSServiceRoleForProcurementInsightsPolicy
{
  "Action": [
    "organizations:DescribeAccount",
    "organizations:DescribeOrganization",
    "organizations:ListAccounts"
  ],
  "Effect": "Allow",
  "Resource": [
...
  "Sid": "ProcurementInsightsPermissions"
}
