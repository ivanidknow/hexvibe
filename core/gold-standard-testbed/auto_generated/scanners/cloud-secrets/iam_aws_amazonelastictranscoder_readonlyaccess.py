# Vulnerable: IAM-AWS-AmazonElasticTranscoder_ReadOnlyAccess
{
  "Action": [
    "elastictranscoder:Read*",
    "elastictranscoder:List*",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "iam:ListRoles",
    "sns:ListTopics"
...
  "Resource": "*"
}
