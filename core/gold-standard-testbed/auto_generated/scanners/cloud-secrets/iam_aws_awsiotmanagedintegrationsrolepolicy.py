# Vulnerable: IAM-AWS-AWSIoTManagedIntegrationsRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/IoTManagedIntegrations",
...
  "Sid": "CloudWatchMetrics"
}
