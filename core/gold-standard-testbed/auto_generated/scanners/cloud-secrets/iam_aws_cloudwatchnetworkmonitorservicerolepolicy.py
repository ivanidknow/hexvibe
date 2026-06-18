# Vulnerable: IAM-AWS-CloudWatchNetworkMonitorServiceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/NetworkMonitor"
...
  }
]
