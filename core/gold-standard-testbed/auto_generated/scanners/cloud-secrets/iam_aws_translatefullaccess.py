# Vulnerable: IAM-AWS-TranslateFullAccess
{
  "Action": [
    "translate:*",
    "comprehend:DetectDominantLanguage",
    "cloudwatch:GetMetricStatistics",
    "cloudwatch:ListMetrics",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
...
  "Resource": "*"
}
