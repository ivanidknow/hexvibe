# Vulnerable: IAM-AWS-AWSBackupDataTransferAccess
{
  "Action": [
    "backup-storage:StartObject",
    "backup-storage:PutChunk",
    "backup-storage:GetChunk",
    "backup-storage:ListChunks",
    "backup-storage:ListObjects",
    "backup-storage:GetObjectMetadata",
...
  "Resource": "*"
}
