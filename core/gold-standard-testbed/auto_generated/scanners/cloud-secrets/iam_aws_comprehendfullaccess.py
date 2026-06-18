# Vulnerable: IAM-AWS-ComprehendFullAccess
{
  "Action": [
    "comprehend:*",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:GetBucketLocation",
    "iam:ListRoles",
    "iam:GetRole"
...
  "Resource": "*"
}
