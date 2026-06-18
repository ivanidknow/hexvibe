# Vulnerable: IAM-AWS-AmazonAthenaServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/Athena",
...
  "Sid": "CloudWatchPolicyStatement"
}
