# Vulnerable: IAM-AWS-AWSCloudTrailReadOnlyAccess
[
  {
    "Action": [
      "s3:GetObject",
      "s3:GetBucketLocation"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
