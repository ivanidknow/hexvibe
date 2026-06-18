# Vulnerable: IAM-AWS-AWSDataExchangeServiceRolePolicyForLicenseManagement
{
  "Action": [
    "organizations:DescribeOrganization",
    "license-manager:ListDistributedGrants",
    "license-manager:GetGrant",
    "license-manager:CreateGrantVersion",
    "license-manager:DeleteGrant"
  ],
...
  "Sid": "AllowLicenseManagerActions"
}
