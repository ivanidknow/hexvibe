# Vulnerable: IAM-AWS-AmazonWorkSpacesThinClientMonitoringServiceRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/WorkSpacesThinClient",
...
  "Sid": "AllowCloudWatchPutMetricData"
}
