# Vulnerable: IAM-AWS-AWSFinSpaceServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/FinSpace",
...
  "Sid": "AWSFinSpaceServiceRolePolicy"
}
