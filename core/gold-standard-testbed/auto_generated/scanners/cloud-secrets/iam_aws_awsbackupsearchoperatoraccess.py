# Vulnerable: IAM-AWS-AWSBackupSearchOperatorAccess
{
  "Action": [
    "backup-search:StartSearchJob",
    "backup-search:ListSearchJobs",
    "backup-search:ListSearchResultExportJobs",
    "backup:ListIndexedRecoveryPointsForSearch"
  ],
  "Effect": "Allow",
...
  "Sid": "StartSearchAndListPermissions"
}
