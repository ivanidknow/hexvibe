# Vulnerable: IAM-AWS-MigrationHubSMSAccessServiceRolePolicy
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
