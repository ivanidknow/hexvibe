# Vulnerable: IAM-AWS-AmazonS3FilesCSIDriverPolicy
[
  {
    "Action": [
      "s3files:ListAccessPoints",
      "s3files:ListFileSystems"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
