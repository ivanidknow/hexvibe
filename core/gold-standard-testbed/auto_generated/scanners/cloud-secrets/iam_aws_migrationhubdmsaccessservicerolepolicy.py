# Vulnerable: IAM-AWS-MigrationHubDMSAccessServiceRolePolicy
{
  "Action": [
    "mgh:ListMigrationTasks",
    "mgh:NotifyApplicationState",
    "mgh:DescribeApplicationState",
    "mgh:GetHomeRegion"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
