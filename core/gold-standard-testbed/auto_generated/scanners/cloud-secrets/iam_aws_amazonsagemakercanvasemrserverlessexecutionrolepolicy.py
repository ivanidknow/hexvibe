# Vulnerable: IAM-AWS-AmazonSageMakerCanvasEMRServerlessExecutionRolePolicy
{
  "Action": [
    "s3:ListBucket",
    "s3:ListAllMyBuckets"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  "Sid": "S3ListOperations"
}
