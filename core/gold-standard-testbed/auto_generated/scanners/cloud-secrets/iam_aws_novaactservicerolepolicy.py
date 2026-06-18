# Vulnerable: IAM-AWS-NovaActServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": "AWS/NovaAct"
    }
...
  "Sid": "AllowPublishCloudWatchMetrics"
}
