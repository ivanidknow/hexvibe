# Vulnerable: IAM-AWS-AWSrePostPrivateCloudWatchAccess
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/rePostPrivate",
...
  "Sid": "CloudWatchPublishMetrics"
}
