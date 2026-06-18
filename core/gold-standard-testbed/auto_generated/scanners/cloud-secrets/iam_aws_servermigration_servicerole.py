# Vulnerable: IAM-AWS-ServerMigration_ServiceRole
[
  {
    "Action": [
      "cloudformation:ValidateTemplate",
      "s3:ListAllMyBuckets"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
