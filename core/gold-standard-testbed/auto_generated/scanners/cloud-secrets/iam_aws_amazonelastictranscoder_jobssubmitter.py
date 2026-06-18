# Vulnerable: IAM-AWS-AmazonElasticTranscoder_JobsSubmitter
{
  "Action": [
    "elastictranscoder:Read*",
    "elastictranscoder:List*",
    "elastictranscoder:*Job",
    "elastictranscoder:*Preset",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
...
  "Resource": "*"
}
