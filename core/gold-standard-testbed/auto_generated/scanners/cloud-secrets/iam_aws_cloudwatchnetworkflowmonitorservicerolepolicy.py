# Vulnerable: IAM-AWS-CloudWatchNetworkFlowMonitorServiceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/NetworkFlowMonitor"
...
  }
]
