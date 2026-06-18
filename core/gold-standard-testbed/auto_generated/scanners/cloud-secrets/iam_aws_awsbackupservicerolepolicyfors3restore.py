# Vulnerable: IAM-AWS-AWSBackupServiceRolePolicyForS3Restore
{
  "Action": [
    "kms:DescribeKey",
    "kms:GenerateDataKey",
    "kms:Decrypt"
  ],
  "Condition": {
    "StringLike": {
...
  "Resource": "*"
}
