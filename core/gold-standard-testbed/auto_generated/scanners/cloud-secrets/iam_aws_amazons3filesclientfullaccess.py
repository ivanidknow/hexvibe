# Vulnerable: IAM-AWS-AmazonS3FilesClientFullAccess
{
  "Action": [
    "s3files:ClientMount",
    "s3files:ClientWrite",
    "s3files:ClientRootAccess"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "S3FilesPermissions"
}
