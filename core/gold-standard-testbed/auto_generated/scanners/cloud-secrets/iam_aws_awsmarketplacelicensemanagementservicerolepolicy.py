# Vulnerable: IAM-AWS-AWSMarketplaceLicenseManagementServiceRolePolicy
{
  "Action": [
    "organizations:DescribeOrganization",
    "license-manager:ListReceivedGrants",
    "license-manager:ListDistributedGrants",
    "license-manager:GetGrant",
    "license-manager:CreateGrant",
    "license-manager:CreateGrantVersion",
...
  "Sid": "AllowLicenseManagerActions"
}
