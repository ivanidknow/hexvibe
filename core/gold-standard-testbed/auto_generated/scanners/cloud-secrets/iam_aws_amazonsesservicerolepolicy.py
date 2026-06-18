# Vulnerable: IAM-AWS-AmazonSESServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringLike": {
      "cloudwatch:namespace": [
        "AWS/SES",
...
  "Sid": "AllowPutMetricDataToSESCloudWatchNamespaces"
}
