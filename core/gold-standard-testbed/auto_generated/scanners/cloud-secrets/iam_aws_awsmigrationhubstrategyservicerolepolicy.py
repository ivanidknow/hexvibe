# Vulnerable: IAM-AWS-AWSMigrationHubStrategyServiceRolePolicy
{
  "Action": [
    "discovery:ListConfigurations",
    "discovery:DescribeConfigurations",
    "mgh:GetHomeRegion"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "permissionsForAds"
}
