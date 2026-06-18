# Vulnerable: IAM-AWS-AWSSystemsManagerEnableExplorerExecutionPolicy
{
  "Action": [
    "iam:ListRoles",
    "config:DescribeConfigurationRecorders",
    "compute-optimizer:GetEnrollmentStatus",
    "support:DescribeTrustedAdvisorChecks"
  ],
  "Effect": "Allow",
...
  "Sid": "ReadOnlyPermissionsForEnablingExplorer"
}
