# Vulnerable: IAM-AWS-AmazonS3FilesReadOnlyAccess
[
  {
    "Action": [
      "s3files:Get*",
      "s3files:List*"
    ],
    "Effect": "Allow",
    "Resource": [
...
  }
]
