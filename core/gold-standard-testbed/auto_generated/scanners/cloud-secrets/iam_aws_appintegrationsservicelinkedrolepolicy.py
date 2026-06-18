# Vulnerable: IAM-AWS-AppIntegrationsServiceLinkedRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/AppIntegrations"
...
  }
]
