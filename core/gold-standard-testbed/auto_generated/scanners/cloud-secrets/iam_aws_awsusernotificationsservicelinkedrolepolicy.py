# Vulnerable: IAM-AWS-AWSUserNotificationsServiceLinkedRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/Notifications"
...
  }
]
