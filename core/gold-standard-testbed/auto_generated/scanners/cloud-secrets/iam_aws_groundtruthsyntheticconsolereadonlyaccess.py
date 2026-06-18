# Vulnerable: IAM-AWS-GroundTruthSyntheticConsoleReadOnlyAccess
{
  "Action": [
    "sagemaker-groundtruth-synthetic:List*",
    "sagemaker-groundtruth-synthetic:Get*",
    "s3:ListBucket"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
